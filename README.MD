
<h1 align="center">
  <br>
  <img src="https://github.com/jhaddix/sus_params/blob/main/sus_banner.png" alt="Sus params" width="750"></a>
</h1>

<h4 align="center">A statisitical analysis of paramters and keywords related to web application vulnerability classes. The `sus_params` project is led by Gunnar Andrews and Jason Haddix.</h4>

<br>

## What is the sus_params Project?

This project is aimed to help new (and seasoned) application security testers when testing enterpise web applications. Often you can land on a large web applications and feel lost as to what to test. The sus_paramaters project is project aimed a giving you insight into parameters or routes that are commonly vulnerable to certain vulnerabilitites. 

When you see them, they are "sus", and you should do manual testing on them for the vulnerability class referenced. 

<br>

## The Vulnerable Paramter Lists

- [Cross-Site Scripting]()
- [Debug and Parameter Tampering](#Sus_params-Debug-and-Parameter-Tampering-Parameters)
- [Server-Side Request Forgery]()
- [File Inclusion - LFI ](#Sus_params-File-Inclusion-/-LFI-Parameters)
- [SQL Injection]()
- [Command Injection](#Sus_params-Command-Injection-Parameters)
- [Open Redirect]()

<br>

## Using Sus_params with GAP

Sus_params data and alerting is now availble via Burp Extention in the AWESOME [GAP](https://github.com/xnl-h4ck3r/GAP-Burp-Extension) Burp extention by [xnl-h4ck3r](https://twitter.com/xnl_h4ck3r)!
 
<br>

## Using GF Pattern Files

The project includes GF pattern files in JSON format to help identify vulnerabilities. Here's how to use them:

1. Gather a list of URLs to inspect. This can be gathered from tools like Burp Suite or [WayMore](https://github.com/xnl-h4ck3r/waymore)
2. Ensure you have `gf` (Grep-Friendly) installed. If not, install it from [here](https://github.com/tomnomnom/gf).
3. Copy the JSON [pattern files](https://github.com/g0ldencybersec/sus_params/tree/main/gf-patterns) to your `gf` patterns directory. Typically, this would be `~/.gf`
4. `gf pattern-name FileOfUrls` (Replace `pattern-name` with the name of the pattern you want to use like `sqli.json`)

<br>

## Whats Next?

Coming soon we will integrate the OWASP Top 25 Parameter data. HUNT's original data, plus the new sus_param data, and the Top 25 should be the ultimate parameter lists!

<br>

## Features

- Comprehensive analysis of Hacktivity Disclosures up to 2023
- Data from platforms like Bugcrowd Crowdstream up to 2023
- Data from all Bugcrowd submissions up until 2016
- Identification of high-risk routes and parameters based on historical data
<br>

## What Else? 

Well this repo is much more than just the data and parameters. Aspiring hackers will notice the full Hacktiviy data dump is hosted [here](https://github.com/g0ldencybersec/sus_params/tree/main/json_files) feel free to use it in your security research! 

We also have the associated code we used parse the data from [Hacktivity](https://github.com/g0ldencybersec/sus_params/blob/main/hackerone.py) and [Bugcrowd](https://github.com/g0ldencybersec/sus_params/blob/main/bugcrowd.py). After we downloaded this we needed to parse the VERY unstructured data to which we used AI for to great effect! (buy Gunnar a beer to maybe see that code). 



### Sus_params **Cross-Site Scripting (XSS)** Parameters

<img src="">

### Sus_params ***Debug and Parameter Tampering*** Parameters

<img src="https://github.com/jhaddix/sus_params/blob/main/debug.png">

### Sus_params **Server-Side Request Forgery (SSRF)** Parameters

<img src="">

### Sus_params **File Inclusion / LFI** Parameters

<img src="https://github.com/jhaddix/sus_params/blob/main/fi.png">

### Sus_params **SQL Injection** Parameters

<img src="">

### Sus_params **Command Injection** Parameters

<img src="https://github.com/jhaddix/sus_params/blob/main/CMDi.png">

### Sus_params **Open Redirect** Parameters

<img src="">
