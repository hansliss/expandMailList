#include <stdlib.h>
#include <stdio.h>
#define __USE_XOPEN
#include <unistd.h>
#include <string.h>
#include <syslog.h>

#define LDAP_DEPRECATED 1

#include <ldap.h>
#include <ldap_cdefs.h>

#define BUFSIZE 131072

#define PRODUCT "expandMailList"
#define VERSION "1.1"

typedef struct stringnode {
  char *string;
  struct stringnode *next;
} *stringstack;

typedef struct stringnode *stringlist;

void pushstring(stringstack *strings, char *s) {
  stringstack old=*strings;
  if (!((*strings)=(struct stringnode *)malloc(sizeof(struct stringnode)))) exit(-253);
  (*strings)->next=old;
  (*strings)->string=strdup(s);
}

char *popstring(stringstack *strings) {
  stringstack top;
  char *res;
  if (*strings == NULL) return NULL;
  top = *strings;
  *strings = (*strings)->next;
  res=top->string;
  free(top);
  return res;
}

void addstring(stringlist *strings, char *s) {
  if (*strings == NULL || strcasecmp((*strings)->string, s) > 0) {
    stringlist newnode=(struct stringnode *)malloc(sizeof(struct stringnode));
    if (!newnode) exit(-253);
    newnode->next=*strings;
    newnode->string=strdup(s);
    (*strings) = newnode;
    return;
  } else if (strcasecmp((*strings)->string, s) < 0) addstring(&((*strings)->next), s);
  else return;
}
    
void printaddress(char *owner, char *address) {
  static char lastowner[BUFSIZE];
  if (strncasecmp(address, "smtp:", 5)) return;
  if (strcasecmp(owner, lastowner)!=0) {
    strcpy(lastowner,owner);
    printf("# %s\n", owner);
  }
  printf("%s\tOK\n", address+5);
}

void usage() {
  fprintf(stderr, "Usage: %s [-b <baseDN>] [-s <server>] [-c <CA certificate file>] [-u <user or bind DN>] [-p <bind password>] [-V (print version)] [-G <group id string - to identify a group DN>]\n", PRODUCT);
}

int main(int argc, char *argv[])
{
  LDAP *ldap;
  int r=0;
  int o;
  static char tmpbuf[BUFSIZE];
  stringstack lists=NULL, people=NULL;

  char *ldapserver="<ldapserver>",
    *ldapcacert="/etc/ssl/certs/<domain>.pem",
    *ldapwho="<domain>\\<user>",
    *ldappassword="<password>",
    *ldapbase="<baseDN>",
    *ldapfilterattr="memberOf",
    *groupidstring="OU=Groups";
  char *ldapattrs[]={"dn", NULL};
  char *ldapattrs2[]={"displayName", "proxyAddresses", "sAMAccountName", NULL};

  while ((o=getopt(argc, argv, "b:s:c:u:p:G:V")) != EOF) {
    switch (o) {
    case 'b': ldapbase = optarg; break;
    case 's': ldapserver = optarg; break;
    case 'c': ldapcacert = optarg; break;
    case 'u': ldapwho = optarg; break;
    case 'p': ldappassword = optarg; break;
    case 'G': groupidstring = optarg; break;
    case 'V': fprintf(stderr, "%s version %s\n", PRODUCT, VERSION); return 0;
    default: usage(); return -1;
    }
  }

  if (optind == argc) {
    usage();
    return -1;
  }

  while (optind < argc) {
    pushstring(&lists, argv[optind++]);
  }

  setenv("LDAPPORT","636",1);
  setenv("LDAPTLS","hard",1);
  setenv("LDAPTLS_CACERT",ldapcacert,1);

  sprintf(tmpbuf, "ldaps://%s:636", ldapserver);
  ldap_initialize(&ldap, tmpbuf);
  if (!ldap)
    {
      fprintf(stderr, "ldap_init() failed\n");
      return -1;
    }

  o=3;
  if ((r = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &o) != LDAP_OPT_SUCCESS)) {
    ldap_perror(ldap, "Setting protocol version");
    ldap_unbind(ldap);
    return -2;
  }

  o = LDAP_OPT_X_TLS_HARD;
  if ((r = ldap_set_option(ldap, LDAP_OPT_X_TLS, &o) != LDAP_OPT_SUCCESS)) {
    ldap_perror(ldap, "Setting TLS mode");
    ldap_unbind(ldap);
    return -2;
  }

  if ((r=ldap_set_option(ldap, LDAP_OPT_X_TLS_CACERTFILE, ldapcacert) != LDAP_OPT_SUCCESS)) {
    //    ldap_perror(ldap, "Setting CA certificate");
    //    fprintf(stderr, "r=%d\n", r);
    //    ldap_unbind(ldap);
    //    return -2;
  }

  if (ldap_simple_bind_s(ldap, ldapwho, ldappassword) != LDAP_SUCCESS) {
    ldap_perror(ldap, "Binding");
    ldap_unbind(ldap);
    return -4;
  }

  char *dn;

  while ((dn = popstring(&lists)) != NULL) {
    /*
    fprintf(stderr, "List: %s\n", dn);
    */
    static char ldapfilter[BUFSIZE];
    // This is for Active Directory, to filter out inactivated accounts. See
    // https://support.microsoft.com/en-us/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro
    sprintf(ldapfilter, "(&(!(useraccountcontrol=514))(%s=%s))", ldapfilterattr, dn);

    LDAPMessage *res;
    if (ldap_search_s(ldap, ldapbase, LDAP_SCOPE_SUBTREE, ldapfilter, ldapattrs, 0, &res) != LDAP_SUCCESS) {
      ldap_perror(ldap, "Search");
      ldap_unbind(ldap);
      return -4;
    }

    LDAPMessage *e=ldap_first_entry(ldap, res);
    while (e) {
      char *dn=ldap_get_dn(ldap, e);
      if (strstr(dn, groupidstring)) pushstring(&lists, dn);
      else {
	addstring(&people, dn);
      }
      e=ldap_next_entry(ldap, e);
    }
    free(dn);
  }

  while ((dn = popstring(&people)) != NULL) {
    /*
    fprintf(stderr, "Person: %s\n", dn);
    */
    LDAPMessage *res;
    if (ldap_search_s(ldap, dn, LDAP_SCOPE_BASE, NULL, ldapattrs2, 0, &res) != LDAP_SUCCESS) {
      ldap_perror(ldap, "Search");
      ldap_unbind(ldap);
      return -4;
    }

    LDAPMessage *e=ldap_first_entry(ldap, res);
    while (e) {
      char **vals=ldap_get_values(ldap, e, "displayName");
      if (vals && vals[0]) {
	char *displayName=strdup(vals[0]);
	if (!vals[0]) {
	  displayName=strdup("<no name>");
	}
	vals=ldap_get_values(ldap, e, "sAMAccountName");
	char *sAMAccountName=strdup(vals[0]);
	/*
	vals=ldap_get_values(ldap, e, "proxyAddresses");
	if (vals) {
	  int n=0;
	  while (vals[n]) {
	    printaddress(displayName, vals[n]);
	    n++;
	  }
	}
	*/
	printf("%s;%s\n", sAMAccountName, displayName);
	free(displayName);
	free(sAMAccountName);
      }
      e=ldap_next_entry(ldap, e);
    }
    free(dn);
  }

  ldap_unbind(ldap);
  return r;
}
