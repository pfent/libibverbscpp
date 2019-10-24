/*
 * Copyright (c) 2010 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under the OpenIB.org BSD license
 * below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AWV
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <getopt.h>
#include <librdmacmcpp.h>

static const char *server = "127.0.0.1";
static const char *port = "7471";

static void run(void)
{
	bool inlineFlag;
	static uint8_t send_msg[16];
	static uint8_t recv_msg[16];

	struct rdma_addrinfo hints;

	memset(&hints, 0, sizeof hints);
	hints.ai_port_space = RDMA_PS_TCP;
	auto res = rdma::addrinfo::get(server, port, &hints);

	ibv::queuepair::InitAttributes attr;
	memset(&attr, 0, sizeof(attr));
	ibv::queuepair::Capabilities cap;
	cap.setMaxSendWr(1);
	cap.setMaxRecvWr(1);
	cap.setMaxSendSge(1);
	cap.setMaxRecvSge(1);
	cap.setMaxInlineData(16);
	attr.setCapabilities(cap);
	attr.setSignalAll(1);
	auto id = rdma::createEP(res, NULL, boost::make_optional(attr));
	// Check to see if we got inline data allowed or not
	if (attr.getCapabilities().getMaxInlineData() >= 16)
		inlineFlag = true;
	else
		printf("rdma_client: device doesn't support IBV_SEND_INLINE, "
		       "using sge sends\n");

	auto mr = id->getPD()->registerMemoryRegion(recv_msg, 16,
						    { ibv::AccessFlag::LOCAL_WRITE });
	auto send_mr = id->getPD()->registerMemoryRegion(send_msg, 16, {});

	auto qp = id->getQP();
	auto recv_wr = ibv::workrequest::Simple<ibv::workrequest::Recv>();
	recv_wr.setLocalAddress(mr->getSlice());
	ibv::workrequest::Recv *bad_recv_wr;
	qp->postRecv(recv_wr, bad_recv_wr);
	id->connect(nullptr);

	auto wr = ibv::workrequest::Simple<ibv::workrequest::Send>();
	ibv::workrequest::SendWr *bad_wr;
	wr.setLocalAddress(send_mr->getSlice());
	if (inlineFlag) {
		wr.setFlags({ ibv::workrequest::Flags::INLINE });
	}
	qp->postSend(wr, bad_wr);

	ibv::workcompletion::WorkCompletion wc;
	auto send_cq = qp->getSendCQ();
	while ((send_cq->poll(1, &wc)) == 0);

	auto recv_cq = id->getQP()->getRecvCQ();
	while ((recv_cq->poll(1, &wc)) == 0);

	id->disconnect();
}

int main(int argc, char **argv)
{
	int op;

	while ((op = getopt(argc, argv, "s:p:")) != -1) {
		switch (op) {
		case 's':
			server = optarg;
			break;
		case 'p':
			port = optarg;
			break;
		default:
			printf("usage: %s\n", argv[0]);
			printf("\t[-s server_address]\n");
			printf("\t[-p port_number]\n");
			exit(1);
		}
	}

	printf("rdma_client: start\n");
	run();
	printf("rdma_client: end\n");
	return 0;
}
