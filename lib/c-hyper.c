/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"

#if !defined(CURL_DISABLE_HTTP) && defined(USE_HYPER)

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include <hyper.h>
#include "urldata.h"
#include "sendf.h"
#include "transfer.h"
#include "multiif.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

static size_t read_cb(void *userp, hyper_context *ctx,
                      uint8_t *buf, size_t buflen)
{
  struct connectdata *conn = (struct connectdata *)userp;
  struct Curl_easy *data = conn->data;
  CURLcode result;
  ssize_t nread;

  (void)ctx;

  result = Curl_read(conn, conn->sockfd, (char *)buf, buflen, &nread);
  if(result == CURLE_AGAIN) {
    /* would block, register interest */
    if(data->hyp.read_waker)
      hyper_waker_free(data->hyp.read_waker);
    data->hyp.read_waker = hyper_context_waker(ctx);
    if(!data->hyp.read_waker) {
      failf(data, "Couldn't make the read hyper_context_waker");
      return HYPER_IO_ERROR;
    }
    return HYPER_IO_PENDING;
  }
  return (size_t)nread;
}

static size_t write_cb(void *userp, hyper_context *ctx,
                       const uint8_t *buf, size_t buflen)
{
  struct connectdata *conn = (struct connectdata *)userp;
  struct Curl_easy *data = conn->data;
  CURLcode result;
  ssize_t nwrote;

  result = Curl_write(conn, conn->sockfd, (void *)buf, buflen, &nwrote);
  if(result == CURLE_AGAIN) {
    /* would block, register interest */
    if(data->hyp.write_waker)
      hyper_waker_free(data->hyp.write_waker);
    data->hyp.write_waker = hyper_context_waker(ctx);
    if(!data->hyp.write_waker) {
      failf(data, "Couldn't make the write hyper_context_waker");
      return HYPER_IO_ERROR;
    }
    return HYPER_IO_PENDING;
  }
  else if(result)
    return HYPER_IO_ERROR;
  return (size_t)nwrote;
}

#define HYPER_ITER_ERROR HYPER_ITER_BREAK /* the best by hyper.h */

static int hyper_each_header(void *userdata,
                             const uint8_t *name,
                             size_t name_len,
                             const uint8_t *value,
                             size_t value_len)
{
  struct Curl_easy *data = (struct Curl_easy *)userdata;
  size_t wrote;
  size_t len;
  curl_write_callback writeheader =
    data->set.fwrite_header? data->set.fwrite_header: data->set.fwrite_func;
  Curl_dyn_reset(&data->state.headerb);
  if(name_len) {
    if(Curl_dyn_addf(&data->state.headerb, "%.*s: %.*s\r\n",
                     (int) name_len, name, (int) value_len, value))
      return HYPER_ITER_ERROR;
  }
  else {
    if(Curl_dyn_add(&data->state.headerb, "\r\n"))
      return HYPER_ITER_ERROR;
  }
  len = Curl_dyn_len(&data->state.headerb);
  if(data->set.verbose)
    Curl_debug(data, CURLINFO_HEADER_IN, Curl_dyn_ptr(&data->state.headerb),
               len);

  Curl_set_in_callback(data, true);
  wrote = writeheader(Curl_dyn_ptr(&data->state.headerb), 1, len,
                      data->set.writeheader);
  Curl_set_in_callback(data, false);
  if(wrote != len)
    return HYPER_ITER_ERROR;

  data->info.header_size += (long)len;
  data->req.headerbytecount += (long)len;
  data->req.bytecount += len;
  return HYPER_ITER_CONTINUE;
}

static int hyper_body_chunk(void *userdata, const hyper_buf *chunk)
{
  char *buf = (char *)hyper_buf_bytes(chunk);
  size_t len = hyper_buf_len(chunk);
  struct Curl_easy *data = (struct Curl_easy *)userdata;
  curl_write_callback writebody = data->set.fwrite_func;
  size_t wrote;

  if(data->set.verbose)
    Curl_debug(data, CURLINFO_DATA_IN, buf, len);
  Curl_set_in_callback(data, true);
  wrote = writebody(buf, 1, len, data->set.out);
  Curl_set_in_callback(data, false);

  if(wrote != Curl_dyn_len(&data->state.headerb))
    return HYPER_ITER_ERROR;

  data->req.bytecount += len;
  return HYPER_ITER_CONTINUE;
}

/*
 * Hyper does not consider the status line, the first line in a HTTP/1
 * response, to be a header. The libcurl API does. This function sends the
 * status line in the header callback. */
static CURLcode status_line(struct Curl_easy *data,
                            uint16_t http_status,
                            int http_version,
                            const uint8_t *reason, size_t rlen)
{
  CURLcode result;
  size_t wrote;
  size_t len;
  const char *vstr;
  curl_write_callback writeheader =
    data->set.fwrite_header? data->set.fwrite_header: data->set.fwrite_func;
  vstr = http_version == HYPER_HTTP_VERSION_1_1 ? "1.1" :
    (http_version == HYPER_HTTP_VERSION_2 ? "2" : "1.0");
  Curl_dyn_reset(&data->state.headerb);

  result = Curl_dyn_addf(&data->state.headerb, "HTTP/%s %03d %.*s\r\n",
                         vstr,
                         (int)http_status,
                         (int)rlen, reason);
  if(result)
    return result;
  len = Curl_dyn_len(&data->state.headerb);
  if(data->set.verbose)
    Curl_debug(data, CURLINFO_HEADER_IN, Curl_dyn_ptr(&data->state.headerb),
               len);
  Curl_set_in_callback(data, true);
  wrote = writeheader(Curl_dyn_ptr(&data->state.headerb), 1, len,
                      data->set.writeheader);
  Curl_set_in_callback(data, false);
  if(wrote != len)
    return CURLE_WRITE_ERROR;

  data->info.header_size += (long)len;
  data->req.headerbytecount += (long)len;
  return CURLE_OK;
}

/*
 * Hyper does not pass on the last empty response header. The libcurl API
 * does. This function sends an empty header in the header callback.
 */
static CURLcode empty_header(struct Curl_easy *data)
{
  return hyper_each_header(data, NULL, 0, NULL, 0) ?
    CURLE_WRITE_ERROR : CURLE_OK;
}

static CURLcode hyperstream(struct Curl_easy *data,
                            struct connectdata *conn,
                            int *didwhat,
                            bool *done,
                            int select_res)
{
  hyper_response *resp = NULL;
  uint16_t http_status;
  int http_version;
  hyper_headers *headers = NULL;
  hyper_body *resp_body = NULL;
  struct hyptransfer *h = &data->hyp;
  hyper_task *task;
  hyper_task *foreach;
  const uint8_t *reason_phrase;
  size_t reason_len;
  (void)conn;

  if(select_res & CURL_CSELECT_IN) {
    if(h->read_waker)
      hyper_waker_wake(h->read_waker);
    h->read_waker = NULL;
  }
  if(select_res & CURL_CSELECT_OUT) {
    if(h->write_waker)
      hyper_waker_wake(h->write_waker);
    h->write_waker = NULL;
  }

  *done = FALSE;
  task = hyper_executor_poll(h->exec);
  if(!task) {
    *didwhat = KEEP_RECV;
    return CURLE_OK;
  }
  else if(h->init) {
    /* end of transfer */
    *done = TRUE;
    infof(data, "hyperstream is done!\n");
    hyper_task_free(task);
    return CURLE_OK;
  }
  else if(hyper_task_type(task) != HYPER_TASK_RESPONSE) {
    *didwhat = KEEP_RECV;
    hyper_task_free(task);
    return CURLE_OK;
  }
  h->init = TRUE;
  *didwhat = KEEP_RECV;
  resp = hyper_task_value(task);
  if(!resp)
    goto error;
  hyper_task_free(task);
  task = NULL;
  http_status = hyper_response_status(resp);
  http_version = hyper_response_version(resp);
  reason_phrase = hyper_response_reason_phrase(resp);
  reason_len = hyper_response_reason_phrase_len(resp);

  if(status_line(data, http_status, http_version, reason_phrase, reason_len))
    goto error;

  headers = hyper_response_headers(resp);
  if(!headers)
    goto error;

  /* the headers seems to already be received? */
  hyper_headers_foreach(headers, hyper_each_header, data);

  if(empty_header(data))
    goto error;

  resp_body = hyper_response_body(resp);
  if(!resp_body)
    goto error;
  foreach = hyper_body_foreach(resp_body, hyper_body_chunk, data);
  if(!foreach)
    goto error;
  hyper_executor_push(h->exec, foreach);

  hyper_response_free(resp); /* done with it? */

  return CURLE_OK;
  error:
  if(task)
    hyper_task_free(task);
  failf(data, "hyperstream ERROR\n");
  return CURLE_OUT_OF_MEMORY;
}

/*
 * Curl_http() gets called from the generic multi_do() function when a HTTP
 * request is to be performed. This creates and sends a properly constructed
 * HTTP request.
 */
CURLcode Curl_http(struct connectdata *conn, bool *done)
{
  struct Curl_easy *data = conn->data;
  struct hyptransfer *h = &data->hyp;
  hyper_io *io = NULL;
  hyper_clientconn_options *options = NULL;
  hyper_task *htask = NULL; /* for the handshake */
  hyper_task *sendtask = NULL; /* for the send */
  hyper_clientconn *client = NULL;
  hyper_request *req = NULL;
  hyper_headers *headers = NULL;
  CURLcode result;
  const char *p_accept; /* Accept: string */
  const char *method;
  Curl_HttpReq httpreq;

  /* Always consider the DO phase done after this function call, even if there
     may be parts of the request that is not yet sent, since we can deal with
     the rest of the request in the PERFORM phase. */
  *done = TRUE;

  infof(data, "Time for the Hyper dance\n");
  memset(h, 0, sizeof(struct hyptransfer));

  result = Curl_http_host(data, conn);
  if(result)
    return result;
  result = Curl_http_useragent(data, conn);
  if(result)
    return result;

  Curl_http_method(data, conn, &method, &httpreq);

  p_accept = Curl_checkheaders(conn, "Accept")?NULL:"Accept: */*\r\n";

  io = hyper_io_new();
  if(!io) {
    failf(data, "Couldn't create hyper IO");
    goto error;
  }
  /* tell Hyper how to read/write network data */
  hyper_io_set_userdata(io, conn);
  hyper_io_set_read(io, read_cb);
  hyper_io_set_write(io, write_cb);

  /* create an executor to poll futures */
  if(!h->exec) {
    h->exec = hyper_executor_new();
    if(!h->exec) {
      failf(data, "Couldn't create hyper executor");
      goto error;
    }
  }

  options = hyper_clientconn_options_new();
  if(!options) {
    failf(data, "Couldn't create hyper client options");
    goto error;
  }
  hyper_clientconn_options_exec(options, h->exec);

  if(!h->handshake) {
    /* "Both the `io` and the `options` are consumed in this function call" */
    h->handshake = hyper_clientconn_handshake(io, options);
    if(!h->handshake) {
      failf(data, "Couldn't create hyper client handshake");
      goto error;
    }
    io = NULL;
    options = NULL;
  }

  if(HYPERE_OK != hyper_executor_push(h->exec, h->handshake)) {
    failf(data, "Couldn't hyper_executor_push the handshake");
    goto error;
  }

  htask = hyper_executor_poll(h->exec);
  if(!htask) {
    failf(data, "Couldn't hyper_executor_poll the handshake");
    goto error;
  }

  client = hyper_task_value(htask);
  hyper_task_free(htask);

  req = hyper_request_new();
  if(!req) {
    failf(data, "Couldn't hyper_request_new");
    goto error;
  }

  if(hyper_request_set_method(req, (uint8_t *)method, strlen(method))) {
    failf(data, "error setting method\n");
    goto error;
  }
  if(hyper_request_set_uri(req, (uint8_t *)data->state.up.path,
                           strlen(data->state.up.path))) {
    failf(data, "error setting path\n");
    goto error;
  }

  headers = hyper_request_headers(req);
  if(!headers) {
    failf(data, "hyper_request_headers\n");
    goto error;
  }

  if(data->state.aptr.host) {
    const char *p = &data->state.aptr.host[6];
    size_t plen = strlen(p) - 2; /* deduct the CRLF pair */
    if(HYPERE_OK != hyper_headers_add(headers, (uint8_t *)"Host", 4,
                                      (uint8_t *)p, plen)) {
      failf(data, "hyper_headers_add host\n");
      goto error;
    }
  }
  if(data->state.aptr.uagent) {
    const char *p = &data->state.aptr.uagent[12];
    size_t plen = strlen(p) - 2; /* deduct the CRLF pair */
    if(HYPERE_OK != hyper_headers_add(headers, (uint8_t *)"User-Agent", 10,
                                      (uint8_t *)p, plen)) {
      failf(data, "hyper_headers_add user-agent\n");
      goto error;
    }
  }
  if(p_accept) {
    const char *p = &p_accept[8];
    size_t plen = strlen(p) - 2; /* deduct the CRLF pair */
    if(HYPERE_OK != hyper_headers_add(headers, (uint8_t *)"Accept", 6,
                                      (uint8_t *)p, plen)) {
      failf(data, "hyper_headers_add accept\n");
      goto error;
    }
  }
  sendtask = hyper_clientconn_send(client, req);
  if(!sendtask) {
    failf(data, "hyper_clientconn_send\n");
    goto error;
  }

  if(HYPERE_OK != hyper_executor_push(h->exec, sendtask)) {
    failf(data, "Couldn't hyper_executor_push the send");
    goto error;
  }

  hyper_clientconn_free(client);

  /* kick off the request */
  (void)hyper_executor_poll(h->exec);

  /* HTTP GET/HEAD download */
  Curl_setup_transfer(data, FIRSTSOCKET, -1, TRUE, -1);
  conn->datastream = hyperstream;

  return CURLE_OK;
  error:

  if(io)
    hyper_io_free(io);

  if(options)
    hyper_clientconn_options_free(options);

  if(h->handshake)
    hyper_task_free(h->handshake);

  return CURLE_OUT_OF_MEMORY;
}

void Curl_hyper_done(struct Curl_easy *data)
{
  struct hyptransfer *h = &data->hyp;
  if(h->exec) {
    hyper_executor_free(h->exec);
    h->exec = NULL;
  }
  if(h->read_waker) {
    hyper_waker_free(h->read_waker);
    h->read_waker = NULL;
  }
  if(h->write_waker) {
    hyper_waker_free(h->write_waker);
    h->write_waker = NULL;
  }
}

#endif /* !defined(CURL_DISABLE_HTTP) && defined(USE_HYPER) */
