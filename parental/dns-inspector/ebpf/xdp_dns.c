// This file is no longer used.
// DNS redirection is now handled by the combined XDP program in:
// parental/ip-filter/xdp_ip_filter.c
//
// That program includes the xsks_map and handles both:
// 1. IP filtering (blocking unregistered IPs)
// 2. DNS redirection to AF_XDP socket for inspection
