/*-
 * Copyright (c) 2014 Semihalf
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/mbuf.h>
#include <sys/socketvar.h>

#include "vr_freebsd.h"
#include "vr_message.h"

static char *
bsd_trans_alloc(unsigned int size)
{
	char *buf;

	buf = malloc(size, M_VROUTER, M_NOWAIT);
	KASSERT((buf != NULL), ("Cannot allocate buf"));
	return (buf);
}

static void
bsd_trans_free(char *buf)
{

	KASSERT((buf != NULL), ("Cannot free NULLed buf"));
	free(buf, M_VROUTER);
}

static struct vr_mtransport bsd_transport = {
	.mtrans_alloc	=	bsd_trans_alloc,
	.mtrans_free	=	bsd_trans_free,
};

int
vr_transport_request(struct socket *so, char *buf, size_t len)
{
	struct vr_message request, *response;
	struct mbuf *m;
	int i;
	int ret;

	request.vr_message_buf = buf;
	request.vr_message_len = len;

	ret = vr_message_request(&request);
	if (ret) {
		free(buf, M_VROUTER);
		vr_log(VR_ERR, "Message request failed, ret:%d\n", ret);
		return (ret);
	}

	free(buf, M_VROUTER);

	while ((response = vr_message_dequeue_response())) {
		/* Create new mbuf and copy response to it */
		m = m_devget(response->vr_message_buf, response->vr_message_len,
		    0, NULL, NULL);

		if (!m) {
			vr_log(VR_ERR, "Cannot create mbuf\n");
			vr_message_free(response);
			return (-1);
		}

		/* Enqueue mbuf in socket's receive sockbuf */
		sbappend(&so->so_rcv, m);
		sorwakeup(so);

		/* Free buffer and response */
		vr_message_free(response);
	}

	return (0);
}

void
vr_transport_exit(void)
{

	vr_message_transport_unregister(&bsd_transport);
}

int
vr_transport_init(void)
{
	int ret;

	ret = vr_message_transport_register(&bsd_transport);
	if (ret) {
		vr_log(VR_ERR, "trasport registration failed:%d\n", ret);
		return (ret);
	}

	return (0);
}
