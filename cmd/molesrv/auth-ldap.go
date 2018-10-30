package main

import (
	"crypto/tls"
	"fmt"
	"log"

	"github.com/mavricknz/ldap"
)

var (
	ldapServer                  = "localhost"
	ldapPort                    = 389
	ldapBind                    = "uid=%s,cn=users"
	ldapSSL                     = false
	ldapBaseDN                  = ""
	ldapBindDN                  = ""
	ldapBindSecretName          = ""
	ldapAttributes     []string = []string{"dn"}
)

func init() {
	authBackends["ldap"] = backendAuthenticateLDAP
	globalFlags.StringVar(&ldapServer, "ldap-host", ldapServer, "(for -auth=ldap) LDAP host")
	globalFlags.IntVar(&ldapPort, "ldap-port", ldapPort, "(for -auth=ldap) LDAP port")
	globalFlags.StringVar(&ldapBind, "ldap-bind", ldapBind, "(for -auth=ldap) LDAP bind template/search template")
	globalFlags.BoolVar(&ldapSSL, "ldap-ssl", ldapSSL, "(for -auth=ldap) Use SSL for LDAP")
	globalFlags.StringVar(&ldapBindDN, "ldap-bind-dn", ldapBindDN, "(for -auth=ldap) LDAP bind user DN")
	globalFlags.StringVar(&ldapBindSecretName, "ldap-bind-secretname", ldapBindSecretName, "(for -auth=ldap) LDAP bind secret keystore name")
	globalFlags.StringVar(&ldapBaseDN, "ldap-base-dn", ldapBaseDN, "(for -auth=ldap) LDAP search base DN")
}

func backendAuthenticateLDAP(user, password string) bool {
	var c *ldap.LDAPConnection
	if ldapSSL {
		config := &tls.Config{
			InsecureSkipVerify: true,
		}
		c = ldap.NewLDAPSSLConnection(ldapServer, uint16(ldapPort), config)
	} else {
		c = ldap.NewLDAPConnection(ldapServer, uint16(ldapPort))
	}
	err := c.Connect()
	if err != nil {
		log.Println("ldap:", err)
		return false
	}
	defer c.Close()
	if ldapBaseDN != "" {
		ldapBindSecret := keys[ldapBindSecretName]
		if ldapBindSecret == "" {
			log.Printf("Could not find ldap secret in key store")
			return false
		}
		err = c.Bind(ldapBindDN, ldapBindSecret)
		if err != nil {
			log.Printf("ldap bind failed: %q: %s", user, err)
			return false
		}
		search_request := ldap.NewSearchRequest(
			ldapBaseDN,
			ldap.ScopeWholeSubtree, ldap.DerefAlways, 0, 0, false,
			fmt.Sprintf(ldapBind, user),
			ldapAttributes,
			nil)
		sr, err := c.Search(search_request)
		if err != nil {
			log.Printf("ldap search failed: %q: %s", user, err)
			return false
		}
		if len(sr.Entries) != 1 {
			log.Printf("ldap search returned wrong number of entries for user: %s", user)
			return false
		}
		userDN := string(sr.Entries[0].DN)
		log.Printf("Authenticating user %s as %s\n", fmt.Sprintf(ldapBind, user), userDN)

		err = c.Bind(userDN, password)
		if err != nil {
			log.Printf("ldap: %q: %s", userDN, err)
			return false
		}
	} else {
		err = c.Bind(fmt.Sprintf(ldapBind, user), password)
		if err != nil {
			log.Printf("ldap: %q: %s", user, err)
			return false
		}
	}

	return true
}
