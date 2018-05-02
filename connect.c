#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>


#define RULE_ENV_NAME "USURP_FW_CFG"
#define DEFAULT_RULE_FILE "./usurp-fw.conf"

int __libusurp_debug_level = 0;

#define debug(lev, ...) { if (getenv("LIBUSURP_DEBUG")) { __libusurp_debug_level=atoi(getenv("LIBUSURP_DEBUG")); } if (__libusurp_debug_level >= lev) printf(__VA_ARGS__); }

#define streq(s1, s2)  (strcmp(s1, s2) == 0)
#define strbegins(s1, s2) (strcasestr(s1, s2) == s1)

struct fw_rule {
    unsigned short allow;
    unsigned long int dest_ip;
    unsigned long int netmask;
    unsigned short start_port;
    unsigned short end_port;
    struct fw_rule *next;   /* linked list */
} ;


struct fw_rule *__libno_rules = NULL;
short int __libno_default_policy_allow = 1;      /* default firewall policy == allow */

/* Strip leading whitespace from a string. Note, modifies the original string */
char *__libno_strip_leading_whitespace(char *buf) 
{
    int length = strlen(buf);
    char *tmpbuf = calloc(length + 1, 1);

    char *p = buf;

    // skip leading whitespace
    while ((*p) && (*p == ' '))
        p++;

    strncpy(tmpbuf, p, strlen(p));
    strncpy(buf, tmpbuf, strlen(tmpbuf));
    free(tmpbuf);
    return buf; 
}


/* chop a string off at the first line break. Note, modifies original string */
char *__libno_chomp(char *buf)
{
    char *p = buf;
    while (*p) {
        if (*p == '\n') 
            *p = '\0';
        p++;
    }
}


/* build up bit pattern matching the IP aaa.bbb.ccc.ddd */
unsigned long int __libno_str_to_ip(char *s)
{
    unsigned long int ip = 0;

    char buf[100];
    bzero(buf, sizeof(buf));

    /* first octet */
    char *p = buf;
    while (*s && (*s != '.')) {
        *(p++) = *(s++);
    }
    ip = (unsigned long int)atoi(buf) << 24;  /* save octet */

    /* stupid error checking */
    if (! (*s))
        return 0;

    /* second octet */
    s++;
    p = buf;
    bzero(buf, sizeof(buf));
    while (*s && (*s != '.')) {
        *(p++) = *(s++);
    }
    ip += (unsigned long int)atoi(buf) << 16;  /* save octet */

    /* stupid error checking */
    if (! (*s))
        return 0;

    /* third octet */
    s++;
    p = buf;
    bzero(buf, sizeof(buf));
    while (*s && (*s != '.')) {
        *(p++) = *(s++);
    }
    ip += (unsigned long int)atoi(buf) << 8;  /* save octet */

    /* stupid error checking */
    if (! (*s))
        return 0;
    
    /* fourth octet */
    s++;
    ip += (unsigned long int)atoi(s);  /* save octet */

    return ip;
}


/* Build a bitmask of c 1s followed by 32 - c 0s (i.e. a netmask) */
unsigned long int __libno_netmask_of_length(short int c)
{
    return (0xffffffff << (32 - c)) & (0xffffffff);
}


/* Read in the __libno_rules config from the defined file. 
   Returns a linked list of fw_rule's. Also sets the globals __libno_default_policy_allow if applicable */
struct fw_rule *__libno_read_config()
{
    char *fn = getenv(RULE_ENV_NAME) ? getenv(RULE_ENV_NAME) : DEFAULT_RULE_FILE;

    /* pointer to hold our __libno_rules... */
    struct fw_rule *__libno_rules = NULL;
    struct fw_rule *cur_rule = NULL;

    FILE *fp;
    if ((fp = fopen(fn, "r"))) {
        char buf[1024];

        int curline = 0;
        while (fgets(buf, sizeof(buf), fp)) {
            curline ++; /* increase lineno */
            __libno_strip_leading_whitespace(buf);
            __libno_chomp(buf);

            if (streq(buf, ""))
                continue;
            if (buf[0] == '#')
                continue;

            /* Handle rule= line */
            if (strbegins((char*)buf, "rule=")) {
                char rule_type[100];
                char rule_ip[100];
                unsigned short rule_mask, rule_port_start, rule_port_end;

                /* parse rule line with sscanf */
                int matched = sscanf(buf, "rule=%s %s %hu %hu %hu", &rule_type, &rule_ip, &rule_mask, &rule_port_start, &rule_port_end);

                if (matched != 5) {
                    printf("** Error: Mismatched rule on line %d in file %s: %s\n", curline, fn, buf);
                    continue;
                }

                /* Now build up a rule */
                struct fw_rule *rule = calloc(sizeof(struct fw_rule), 1);
                rule->allow = strbegins(rule_type, "allow");
                rule->dest_ip = __libno_str_to_ip(rule_ip);
                rule->netmask = __libno_netmask_of_length(rule_mask);
                rule->start_port = rule_port_start;
                rule->end_port = rule_port_end;
                rule->next = NULL;

                /* inject rule */
                if (cur_rule == NULL) {
                    /* first rule */
                    __libno_rules = rule;
                } else {
                    /* we already have __libno_rules */
                    cur_rule->next = rule;
                }
                cur_rule = rule;
            }

            /* handle default policy */
            if (strbegins(buf, "default_policy=")) {
                __libno_default_policy_allow = strbegins(buf, "default_policy=allow");
            }
        }
        fclose(fp);
    }
    else {
        printf("Failed to open config file %s - use %s env to define!\n", fn, RULE_ENV_NAME);
    }

    return __libno_rules;
}


void __libno_dump_rules()
{
    struct fw_rule *r = __libno_rules;
    debug(1, "Default policy: %d\n", __libno_default_policy_allow);
    while (r) {
        debug(1, "  RULE:  allow=%d\n", r->allow);
        debug(1, "         dest_ip = %lx\n", r->dest_ip);
        debug(1, "         netmask = %lx\n", r->netmask);
        debug(1, "         ports = %d - %d\n", r->start_port, r->end_port);
        
        r = r->next;
    }
}


/* Read in __libno_rules */
void __libno_build_rules()
{
    if (__libno_rules == NULL) {
        /* Only read __libno_rules once! */
        __libno_rules = __libno_read_config();
        __libno_dump_rules();
    }
}


/* Check if an ip is in a particular subnet/mask */
int __libno_is_in_subnet(unsigned long int ip, unsigned long int net, unsigned long int netmask)
{
    return (ip & netmask) == net;
}


/* don't forget to free... */
char *__libno_ip_to_str(unsigned long int ip)
{
    short int maxlen = 4 * 3 + 4;
    char *s = malloc(maxlen + 1);  // enough for aaa.bbb.ccc.dddE
  
    int a = (ip & 0xff000000) >> 24;
    int b = (ip & 0xff0000) >> 16;
    int c = (ip & 0xff00) >> 8;
    int d = (ip & 0xff);

    snprintf(s, maxlen, "%03d.%03d.%03d.%03d", a, b, c, d);
    return s;
}


/* Match __libno_rules against IP - return the policy for the first found rule, or the default policy 
   if none found. */
unsigned short __libno_run_rules(struct fw_rule *r, unsigned long int ip, unsigned short port)
{
    struct fw_rule *cur_rule = r;

    debug(2, "__libno_run_rules:  ip = %x,  port = %d, r = %x\n", ip, port, r);

    while (cur_rule) {
        /* check ip subnet */

        debug(2, "  RULE:  allow=%d\n", cur_rule->allow);
        debug(2, "         dest_ip = %x\n", cur_rule->dest_ip);
        debug(2, "         netmask = %x\n", cur_rule->netmask);
        debug(2, "         ports = %d - %d\n", cur_rule->start_port, cur_rule->end_port);

        if (__libno_is_in_subnet(ip, cur_rule->dest_ip, cur_rule->netmask)) {
            debug(3, "ip %x is in subnet %x/%u\n", ip, cur_rule->dest_ip, cur_rule->netmask);
            if ((cur_rule->start_port <= port) && (cur_rule->end_port >= port)) {    
                debug(3, "port %d matches. Returning %d\n", port, cur_rule->allow);
                return cur_rule->allow;
            } 
        }
        cur_rule = cur_rule->next;
    }
    
    debug(2, "Hit default policy: %d\n", __libno_default_policy_allow);
    return __libno_default_policy_allow;
}


/* Here's the magic - preload connect() and check if we should be allowed to connect to 
   a particular IP. If not, we return -1 and set errno to EACCESS. If yes, we call the original
   connect() */
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    int (*org_connect)(int, const struct sockaddr *, socklen_t);
    org_connect = dlsym(RTLD_NEXT, "connect"); 

    if (addr->sa_family == AF_INET) { 
        __libno_build_rules(); /* leaky leak - but only once */

        const struct sockaddr_in *sin = (const struct sockaddr_in*)addr;

        unsigned long int remote_ip = htonl(sin->sin_addr.s_addr);
        unsigned short translated_port = htons(sin->sin_port);
        char *ip_string = __libno_ip_to_str(remote_ip);
        debug(3, "translated_port = %d\n", translated_port);
        debug(3, "Remote IP as a string: %s\n", ip_string);
        free(ip_string);

        debug(4, "   org_connect = %x\n", org_connect);

        if (__libno_run_rules(__libno_rules, remote_ip, translated_port)) {
            debug(1, "Allowing connection!\n");
            return (*org_connect)(sockfd, addr, addrlen);
        } 
        else {
            debug(1, "*** DENIED ***\n");
            errno = EACCES;
            return -1;
        }
    }
    else {
        /* We're only interested in IPV4 */
        return (*org_connect)(sockfd, addr, addrlen);
    }
}
