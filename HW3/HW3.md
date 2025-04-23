# NYCU NA 2025 HW3

#### Spec: https://nasa.cs.nycu.edu.tw/na/2025/slides/hw3.pdf

#### OS: Debian 12.9.0

---

# Router

#### Edit /etc/dhcp/dhcpd.conf

```vim=
option domain-name-servers 192.168.4.153;         // My Resolver

host mail {
    hardware ethernet <Mail Server MAC Addr>;
    fixed-address 192.168.4.25;
}
```

# Authoritative DNS Server

## BIND9

### Edit /var/cache/bind/db.4.nasa

Add MX record, SPF, DMARC, DKIM
```vim=
$TTL 86400
$ORIGIN 4.nasa.
@       IN  SOA  ns1.4.nasa. admin.4.nasa. (
            2025033101  ; Serial
            3600        ; Refresh
            1800        ; Retry
            604800      ; Expire
            86400 )     ; Minimum TTL
        IN  NS  ns1.4.nasa.
        IN  MX  10  mail.4.nasa.
        IN  TXT "v=spf1 ip4:192.168.4.25 -all"
_dmarc  IN  TXT "v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:dmarc-report-rua@4.nasa;"
mail    IN  MX  10  mail.4.nasa.
mail    IN  A   192.168.4.25
whoami  IN  A   10.113.4.1
dns     IN  A   192.168.4.153
ns1     IN  A   192.168.4.53
mail._domaikey          IN  TXT ( "v=DKIM1; h=sha256; k=rsa;" "p=..." "...")
mailmail._domaikey.mail IN  TXT ( "v=DKIM1; h=sha256; k=rsa;" "p=..." "...")

$INCLUDE "/var/cache/bind/K4.nasa.+013+<ZSK_ID>.key"
$INCLUDE "/var/cache/bind/K4.nasa.+013+<KSK_ID>.key"
```
>Note: You can add DKIM later

### Edit /var/cache/bind/db.192.168.4

```vim=
$TTL 86400
$ORIGIN 4.168.192.in-addr.arpa.
@   IN  SOA  ns1.4.nasa. admin.4.nasa. (
            2025033101  ; Serial
            3600        ; Refresh
            1800        ; Retry
            604800      ; Expire
            86400 )     ; Minimum TTL
    IN  NS   ns1.4.nasa.
53  IN  PTR  ns1.4.nasa.
153 IN  PTR  dns.4.nasa.
25  IN  PTR  mail.4.nasa.

$INCLUDE "/var/cache/bind/K4.168.192.in-addr.arpa.+013+<ZSK_ID>.key"
$INCLUDE "/var/cache/bind/K4.168.192.in-addr.arpa.+013+<KSK_ID>.key"
```

### Resign Zones

```bash
sudo dnssec-signzone -g -o 4.nasa -k K4.nasa.+013+<KSK_ID>.key db.4.nasa K4.nasa.+013+<ZSK_ID>.key
sudo dnssec-signzone -g -o 4.168.192.in-addr.arpa -k K4.168.192.in-addr.arpa.+013+<KSK_ID>.key db.4.168.192 K4.168.192.in-addr.arpa.+013+<ZSK_ID>.key
```

### Restart service

```bash
sudo systemctl restart bind9
```

### Test

```bash
sudo dig @192.168.4.53 mail.4.nasa. MX +dnssec
sudo dig @192.168.4.53 4.nasa. TXT +dnssec
sudo dig @192.168.4.53 _dmarc.4.nasa. TXT +dnssec
sudo dig @192.168.4.53 mail._domaikey.4.nasa. TXT +dnssec
```
>Note: Remember to restart the `named`/`unbound` in Resolver (refresh the cache)

# Mail Server

* Get the certificates from SysJudge and store then in `nasa_crt.pem`, `nasa_key.pem`, `nasa_ca.pem`

* If you don't want to type the password (32 char) manually, you can put it in `pw.txt`

## Add users
```bash=
sudo adduser ta
sudo adduser cool-ta
cat pw.txt | sudo chpasswd
```
## POSTFIX

```bash
sudo apt install postfix
```

### Edit /etc/postfix/main.cf

```vim=
# Network and domain settings
    myhostname = mail.4.nasa
    mydomain = 4.nasa
    myorigin = $mydomain                                                        // default domain of sending mail from local
    mydestination = $myhostname, $mydomain, localhost.$mydomain, localhost      // what domains Postfix will deliver locally
    inet_interfaces = all                                                       // what interfaces Postfix will use
    mynetworks = 127.0.0.0/8 192.168.4.0/24                                     // what network Postfix will open relay
    recipient_delimiter = +

# STARTTLS 
    smtpd_tls_cert_file = /etc/ssl/certs/nasa_cert.pem
    smtpd_tls_key_file = /etc/ssl/private/nasa_key.pem
    smtpd_tls_security_level = may
    smtp_tls_CApath = /etc/ssl/certs/nasa_ca.pem
    smtp_tls_security_level = may
    smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache

# SASL Authentication
    smtpd_sasl_type = dovecot
    smtpd_sasl_path = private/auth
    smtpd_sasl_auth_enable = yes

# Restrictions
    smtpd_sender_restrictions =
        reject_unauthenticated_sender_login_mismatch,                           // rejects unauthenticated clients if their "MAIL FROM" address is listed in "smtpd_sender_login_maps"
        reject_authenticated_sender_login_mismatch,                             // rejects authenticated clients if their "MAIL FROM" address doesn’t match [an address] mapped to [their SASL username] in "smtpd_sender_login_maps".
        reject_unlisted_sender,                                                 // rejects emails if the sender address’s domain isn’t in "mydestination", "virtual_alias_domains", and the address isn’t in "smtpd_sender_login_maps".
        check_sender_access hash:/etc/postfix/sender_access                     // the rule of checking sender
    smtpd_sender_login_maps = hash:/etc/postfix/sender_login_maps               // enforces sender authentication by mapping "MAIL FROM" addresses to authenticated user logins (SASL usernames)
    smtpd_recipient_restrictions =
        reject_unknown_recipient_domain                                         // rejects emails if their "RCPT TO" domain isn’t resolvable via DNS or listed in "mydestination", "virtual_alias_domains"
        check_policy_service inet:127.0.0.1:10023                               // queries an external policy service (Postgrey)
    smtpd_relay_restrictions =
        permit_mynetworks,
        permit_sasl_authenticated
        defer_unauth_destination

# Outgoing header check
    header_checks = regexp:/etc/postfix/outgoing_header_checks

# Incoming content filter
    content_filter = smtp-amavis:[127.0.0.1]:10024                              //forward to amavis at localhost:10024

# Virtual alias mapping (rewrites recipient addresses)                               
    alias_database = hash:/etc/aliases                                          
    alias_maps = hash:/etc/aliases                                              // Handles local aliasing for email addresses within domains listed in "mydestination"
    #virtual_alias_maps = regexp:/etc/postfix/virtual                           // Handles virtual aliasing for email addresses across "any domain"

# Sender rewriting
    smtp_generic_maps = regexp:/etc/postfix/sender_canonical

# DKIM
    smtpd_milters = inet:127.0.0.1:8891
    non_smtpd_milters = inet:127.0.0.1:8891
    milter_default_action = accept
```

### Create /etc/postfix/sender_access

Reject null sender
```vim=
<> REJECT
```
```bash
sudo postmap /etc/postfix/sender_access
```

### Create /etc/postfix/sender_login_maps

Mapping "MAIL FROM" addresses to authenticated user logins (SASL usernames)
```vim=
TA@4.nasa           ta
TA@mail.4.nasa      ta
cool-TA@4.nasa      cool-ta
cool-TA@mail.4.nasa cool-ta
```
```bash
sudo postmap /etc/postfix/sender_login_maps
```

### Create /etc/aliases

Rewrites recipient addresses to local usernames
```vim=
postmaster:     root
NASATA:         ta
/^TA\+.*$/:     ta
TA:             ta
cool-TA:        cool-ta
```
```bash
sudo postalias /etc/aliases
```


**Another method**: you can write this using virtual_alias_maps.

Rewrites recipient addresses to other addresses
```vim=
/^NASATA@(.*)$/    ta@${1}
/^TA\+.*@(.*)$/    ta@${1}
/^TA@(.*)$/        ta@${1}
/^cool-TA@(.*)$/   cool-ta@${1}
```

### Create /etc/postfix/sender_canonical

Sender rewrite
```vim=
/^cool-TA@(.*)$/        supercoool-TA@${1}
/^(.*)@mail\.4\.nasa$/  ${1}@4.nasa
```

#### Create /etc/postfix/outgoing_header_checks

Reject mails whose subject contains keyword:
* Graduate School
* 博士班 (use UTF-8 coding)
```vim=
/^Subject:.*Graduate School/ REJECT
/^Subject:.*\=\?UTF-8\?B\?5Y2a5aOr54\+t\?\=/ REJECT
```

### For debug:

```bash
sudo postfix check
sudo postfix reload
```

## DOVECOT (IMAP)

```bash
sudo apt install dovecot-imapd dovecot-pop3d
```

### Edit /etc/dovecot/conf.d/10-master.conf

```vim=
service auth {
    unix_listener /var/spool/postfix/private/auth {
        mode = 0666
    }
}
```

### Edit /etc/dovecot/conf.d/10-ssl.conf

```vim=
ssl = yes
ssl_cert = </etc/ssl/certs/nasa_cert.pem
ssl_key = </etc/ssl/private/nasa_key.pem
ssl_client_ca_dir = /etc/ssl/certs
```

### Edit /etc/dovecot/conf.d/10-auth.conf
```vim=
disable_plaintext_auth = yes
auth_mechanisms = plain login
```

### Edit /etc/dovecot/conf.d/10-logging.conf     (for debug)
```vim=
// ensure rsyslog is enable
log_path = syslog
info_log_path =
debig_log_path = 
syslog_facility = mail
```
### Edit /etc/dovecot/conf.d/10-mail.conf

you can change the location of mailbox

```vim=
mail_location = mbox:~/mail:INBOX=/var/mail/%u     
```

## POSTGREY

```bash
sudo apt install postgrey
```

### Edit /etc/default/postgrey

```vim=
POSTGREY_OPTS="--inet=10023 --delay=15"
```

### Edit /etc/postgrey/whitelist_clients

```vim=
ta.nasa
```

## DKIM
```bash
sudo apt install opendkim
```

### Generate Key Pair

```bash
sudo mkdir /etc/opendkim/keys/4.nasa
sudo mkdir /etc/opendkim/keys/mail.4.nasa

sudo opendkim-genkey -D /etc/opendkim/keys/4.nasa/ -d 4.nasa -s mail
#    generate    mail.private    mail.txt
sudo opendkim-genkey -D /etc/opendkim/keys/mail.4.nasa/ -d mail.4.nasa -s mailmail
#    generate    mailmail.private    mailmail.txt

sudo chown -R opendkim:opendkim /etc/opendkim/keys/
```
> Note: You can choose other selector

### Transmit public key to Authoritative DNS Server

```bash
sudo scp /etc/opendkim/keys/4.nasa/mail.txt dns@192.168.4.53:/home/dns
sudo scp /etc/opendkim/keys/mail.4.nasa/mailmail.txt dns@192.168.4.53:/home/dns
```
#### On Authoritative DNS server
```bash    
cat ~/mail.txt >> /var/cache/bind/db.4.nasa
cat ~/mailmail.txt >> /var/cache/bind/db.4.nasa
```
> Note: Remember to resign the zone

### Edit /etc/opendkim.conf

```vim=
*   Mode                sv                                      // s代表寄出時簽章、v代表收信時檢查簽章。
    OversignHeaders     From
    SignatureAlgorithm  rsa-sha256
    Domain              4.nasa,mail.4.nasa
    Selector            mail
*   InternalHosts       refile:/etc/opendkim/TrustedHosts       // InternalHosts 寄出的信都要加上簽章, ExternalIgnoreList   設定寄出的信都不要加上簽章 
*   SigningTable        refile:/etc/opendkim/SigningTable       // mapping the address found in the From: header to key name
*   KeyTable            /etc/opendkim/KeyTable                  // mapping key name to key file
    UserID              opendkim
    UMask               007
    Socket              local:/run/opendkim/opendkim.sock
*   Socket              local:8891@localhost                    // listen on port 8891
    PidFile             /run/opendkim/opendkim.pid
*   Nameserver          192.168.254.153                         // default nameserver to search DKIM
*   #TrustAnchorFile       /usr/share/dns/root.key              // comment this can fix "OpenDKIM query timed out"
``` 
> Note: `*` means important setting

### Create /etc/opendkim/TrustedHosts

```vim=
4.nasa
192.168.4.25
127.0.0.1
```

### Create /etc/opendkim/SigningTable

```vim=
*@4.nasa        mail._domaikey.4.nasa
*@mail.4.nasa   mailmail._domaikey.mail.4.nasa
```

### Create /etc/opendkim/KeyTable

`<Selector>._domainkey.<Domain name>` `<Domain name>`:`<Selector>`:`<Path to Private>`
    
```vim=
mail._domaikey.4.nasa               4.nasa:mail:/etc/opendkim/keys/4.nasa/mail.private
mailmail._domaikey.mail.4.nasa      mail.4.nasa:mailmail:/etc/opendkim/keys/mail.4.nasa/mailmail.private
```    
    
## Amavis, SpamAssassin

```bash
sudo apt install amavis-new spamassassin
```

### Edit /etc/spamassassin/local.cf

```vim=
rewrite_header Subject **SPAM**
report_safe 0
use_bayes 0
```

### Edit /etc/amavis/conf.d/05-node_id

```vim=
$myhostname = "mail.4.nasa";
```

### Edit /etc/amavis/conf.d/15-content_filter_mode

```vim=
@bypass_spam_checks_maps = (
    \%bypass_spam_checks,   \@bypass_spam_checks_acl,   \$bypass_spam_checks_re
);
```

### Edit /etc/amavis/conf.d/50-user

```vim=
$log_level = 2;
$syslog_facility = 'mail';
$syslog_priority = 'info';

$forward_method = 'smtp:127.0.0.1:10025';               // forward back to postfix
$sa_tag2_level_deflt = 2.0;                             // spam detect level
$sa_spam_modifies_subj = 1;                             // enable subject modify
$sa_spam_subject_tag = '**SPAM**';                      // prepend subject tag
$final_spam_destiny = D_PASS;                           // pass the mail
@local_domains_maps = ( ['4.nasa', 'mail.4.nasa'] );
```

### Edit /etc/postfix/master.cf

Copy from [15_AdvanceMail](https://nasa.cs.nycu.edu.tw/na/2024/slides/15_AdvancedMail.pdf "15_AdvanceMail") page 78 

```vim=   
smtp-amavis     unix    -   -   n   -   10  smtp
    -o smtp_data_done_timeout=1200s
    -o smtp_never_send_ehlo=yes
    -o notify_classes=protocol,resource,software
127.0.0.1:10025 inet    n   -   n   -   -   smtpd
    -o content_filter=
    -o mynetworks=127.0.0.0/8
    -o local_recipient_maps=
    -o notify_classes=protocol,resource,software
    -o myhostname=localhost
    -o smtpd_client_restrictions=
    -o smtpd_sender_restrictions=
    -o smtpd_recipient_restrictions=permit_mynetworks,reject
    -o smtpd_tls_security_level=
```

```bash
sudo sa-update
```

## Test:

Some command to encoding the username and password to `Base64`

```bash
echo -n "text" | base64
printf '\0username\0password' | base64
```

### smtp

`LOGIN`
```smtp
openssl s_client -connect mail.4.nasa:25 -starttls smtp
EHLO mail.4.nasa
AUTH LOGIN
<base64_username> 
<base64_password>
MAIL FROM: <sender_address>
RCPT TO: <recipient_address>
DATA
<mail_content>
.
QUIT
```

`PLAIN`
```smtp
openssl s_client -connect mail.4.nasa:25 -starttls smtp
EHLO mail.4.nasa
AUTH PLAIN
<base64_'\0username\0password'>
MAIL FROM: <sender_address>
RCPT TO: <recipient_address>
DATA
<mail_content>
.
QUIT
```

### imap

```imap
openssl s_client -connect mail.4.nasa:143 -starttls imap
a1 login username password
a2 list "" "*"
a3 select INBOX
```