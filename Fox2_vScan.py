# -*- coding:utf-8 -*-

import re
import httplib
import time
import os
import optparse
from urlparse import urlparse

# CopyRight By Misty, KISA(한국인터넷진흥원 연구센터), KUCIS 서경강
# 악성코드로 의심되는 파일을 vscan.novirusTanks.org에 업로드하여 악성코드 분석 결과값을 파싱해서 가져온다.
# 실행은 다음과 같이 가능하다.
"""
python Fox2_vscan -f TestMalware.exe
"""
# 와 같이 실행하여 해당 파일이 악성코드인지 판별하는 자동 스크립트임.

# 의심스러운 파일을 업로드하고 스캐닝 결과를 출력함.
"""
스크립트가 파일 페이지에 연결하고, 이 페이지는 스캐닝중이라는 메세지를 반환한다.
그 후, HTTP 302코드를 반환하면 정규표현식을 사용하여 탐지율을 읽어오고 CSS 코드를 공란으로 대체한다.
그리고는 탐지 결과를 화면에 출력한다.
"""
def PrintResult(url):
    status = 200
    host = urlparse(url)[1]
    path = urlparse(url)[2]
    if 'analysis' not in path:
        while status != 302:
            conn = httplib.HTTPConnection(host)
            conn.request('GET', path)
            resp = conn.getresponse()
            status = resp.status
            print '[+] ', 'Scanning File..../'
            conn.close()
            time.sleep(15)
    print '[+] ', 'Scan Complete.'
    path = path.replace('file', 'analysis')
    conn = httplib.HTTPConnection(host)
    conn.request('GET', path)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    reResults = re.findall(r'Detection rate:.*\) ', data)
    htmlStrinpRes = reResults[1].\
        replace('&lt;font color=\'red\'&gt;', '').\
        replace('&lt;/font&gt;', '')
    print '[+] ' + str(htmlStrinpRes)


#  파일 업로드 하기. 파일 이름을 HTML 파라미터로 설정하여 스크립트를 작성하였음.
"""
파일을 열고 내용을 읽은 다음에, 스크립트는 vscan.novirusthanks.org에 연결하고 헤더와 데이터 파라미터를
포스팅한다. 그리고는 업로드된 파일의 분석이 포함되어 있는 페이지에 대한 링크를 응답으로 받는다.
"""
def uploadFile(Fox2_filename):
    print '[+] ', 'Uploading File to noVirusThanks.../'
    fileContents = open(Fox2_filename, 'rb').read()
    header = {'Content-Type': 'multipart/form-data; \
              boundary=----WebKitFormBoundaryF17rwCZdGuPNPT9U'}
    Fox_params = "------WebKitFormBoundaryF17rwCZdGuPNPT9U"
    Fox_params += "\r\nContent--Disposition: form-data; " +\
        "name=\"upfile\"; filename=\""+str(Fox2_filename)+"\""
    Fox_params += "\r\nContent-Type: "+\
        "application/cotet stream\r\n\r\n"
    Fox_params += fileContents
    Fox_params += "\r\n------WebKitFormBoundaryF17rwCZdGuPNPT9U"
    Fox_params += "\r\nContent-Disposition: form-data; "+\
        "name=\"submitfile\"\r\n"
    Fox_params += "\r\nSubmit file\r\n"
    Fox_params += "------WebKitFormBoundaryF17rwCZdGuPNPT9U--\r\n"

    conn = httplib.HTTPConnection(' vscan.novirusthanks.org ')
    conn.request("POST", "/", Fox_params, header)
    response = conn.getresponse()
    location = response.getheader('location')
    conn.close()

    return location

def main():
    parser = optparse.OptionParser('usage%prog -f <filename>')
    parser.add_option('-f', dest='Fox2_filename', type='string', \
                      help='specify filename')
    (options, args) = parser.parse_args()
    Fox2_filename = options.Fox2_filename
    if Fox2_filename == None:
        print parser.usage
        exit(0)
    elif os.path.isfile(Fox2_filename) == False:
        print '[+] ', + Fox2_filename + 'does not exist...T.T'
        exit(0)
    else:
        loc = uploadFile(Fox2_filename)
        printResults(loc)


