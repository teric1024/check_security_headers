# securityheaders
Python script to check HTTP security headers

Written and tested using Python 3.12.

With minor modifications could be used as a library for other projects.

## Usage
securityheaders.py
```
$ python securityheaders.py --help
usage: securityheaders.py [-h] [--max-redirects N] URL

Check HTTP security headers

positional arguments:
  URL                Target URL

optional arguments:
  -h, --help         show this help message and exit
  --max-redirects N  Max redirects, set 0 to disable (default: 2)
$
```
urls_batch_check.py
```
usage: urls_batch_check.py [-h] [--target_url_file TARGET_URL_FILE] [--output_csv OUTPUT_CSV]

Check HTTP security headers

options:
  -h, --help            show this help message and exit
  --target_url_file TARGET_URL_FILE
                        txt file including urls (default: urls.txt)
  --output_csv OUTPUT_CSV
                        result csv file path (default: output.csv)
```


## Output
securityheaders.py
```
$ python securityheaders.py --max-redirects 5 https://secfault.fi
Header 'x-xss-protection' is missing ... [ WARN ]
Header 'x-content-type-options' is missing ... [ WARN ]
Header 'content-security-policy' is missing ... [ WARN ]
Header 'x-powered-by' is missing ... [ OK ]
Header 'x-frame-options' contains value 'DENY' ... [ OK ]
Header 'strict-transport-security' contains value 'max-age=63072000' ... [ OK ]
Header 'access-control-allow-origin' is missing ... [ OK ]
Header 'server' contains value 'nginx/1.10.1' ... [ WARN ]
HTTPS supported ... [ OK ]
HTTPS valid certificate ... [ OK ]
HTTP -> HTTPS redirect ... [ OK ]
$
```

## Reference
- [OWASP cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-xss-protection)
- https://securityheaders.com/

## Note
This is largely based on the work of [@juerkkil](https://github.com/juerkkil). 

[original repo](https://github.com/juerkkil/securityheaders) 