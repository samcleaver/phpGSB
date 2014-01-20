# Implementation of Google Safe Browsing

**phpGSB** is a robust implementation of the Google Safe Browsing API. It currently *does* allow the following:

* Updating of GSB lists to a MySQL database
* Basic checking of URLs' against lists and then full-hash checks against the full GSB database
* Caching of full-hash keys to minimise requests to the remote Google server

At current it *does not* allow the following:

* Requests using MAC keys (integrity checks)

The main class is definitely not as efficient as it could be and has developed very quickly to meet the basic GSB specification; any contributions, bug fixes etc are **very** welcome! 

## Download

* Installation using composer
```
$ composer require samcleaver/phpgsb
```

* You could manually download phpgsb by this link: https://github.com/samcleaver/phpGSB/archive/0.2.4.zip

## Installation

1. Enter database details into install.php (Replace DATABASE_USERNAME, DATABASE_NAME and DATABASE_PASSWORD with respective information)
2. Run install.php
3. Look at listupdater.php and lookup.php example files for basic methods on using the system.
4. If you choose to use listupdater.php as-is then set it as a cron job/scheduled task to run every minute. *(It won't actually update every minute but is required incase of backoff procedures and timeouts)*

## FAQ

* **When I do a lookup, phpGSB says the URL is safe but I know it's not.**
*The database is updated in chunks from Google's central server. Because of this, you need to run updates for 24 hours before you can start doing lookups, this is a limitation of the specification and not the implementation. (Check Step 5 of installation on how to ensure updates are running.)*

## License

The phpGSB library is released under the New BSD License.

```
Copyright (c) 2010-2012, Sam Cleaver

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the organization nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL SAM CLEAVER BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```