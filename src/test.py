#!/usr/bin/python
import requests
import sys
import time
from time import clock
#from flask import request
#address = 'http://122.152.202.95:5001/'
address = 'http://123.206.74.17:5001/'
def upload(filename):
	#url = 'http://115.159.84.230:5001/'
	url = address
	files = {'file':open(filename,'rb')}
	r = requests.post(url,files=files)
	#print r.status_code
	#print r.url
	#print r.text
	code = 200 
	#time.sleep(10)
	if r.status_code==code:
		print 'upload code 200'
		sys.exit(0)
	else:
		print 'code != 200'
		sys.exit(1)	

def upload_time(filename):
        url = 'http://115.159.84.230:5001/'
        files = {'file':open(filename,'rb')}
        r = requests.post(url,files=files)
        #print r.status_code
        #print r.url
        #print r.text
        code = 200 
        if r.status_code==code:
                #print 'code 200'
		i=1               
        else:
                print 'code != 200'
                sys.exit(0) 
	
def download(filename):
	#url =  'http://115.159.84.230:5001/uploads/'+filename
	url = address+'uploads/'+filename
	r = requests.get(url)
	print r.status_code
	print r.url
	#file = r.text
	path='//home//lyc//ntl//tuples//'
        fh=open(path+filename,'wb')
	fh.write(r.content)
	fh.close()

	if r.status_code==200:
		print 'download code 200'
		sys.exit(1)
	else:
		print 'code!=200'
		sys.exit(0)

def download_time(path,filename):
        url =  'http://115.159.84.230:5001/uploads/'+filename
        r = requests.get(url)
        print r.status_code
        print r.url
        #file = r.text
        fh=open(path+filename,'wb')
        fh.write(r.content)
        fh.close()

        if r.status_code==200:
                print 'code 200'
        else:
                print 'code!=200'
                sys.exit(0)


def delete(filename):
	url =  'http://115.159.84.230:5001/delete/'+filename
	r = requests.get(url)
	print r.status_code
	print r.text
	if r.status_code==200:
		sys.exit(1)
	else: 
		sys.exit(0)

def main(option):
	if option=='download':
		download(sys.argv[2])
	if option=='upload':
		upload(sys.argv[2])
	if option=='delete':
		delete(sys.argv[2])
	if option=='upload_time':
		start = clock()
		for i in sys.argv[2:]:
			upload_time(i)
		end = clock()
		fo=open("//home//lyc//test_file//uploadtime.txt","a")
		time = end -start
		seq='time:'+str(time)+'\n'
		fo.writelines(seq)
		fo.close()
		#print end-start
	if option=='test_download':
		start = clock()
		for i in range(1,2,1):	
			download_time(sys.argv[2],sys.argv[3])
		end = clock()
		print end - start
	if option=='test_upload':
		start=clock()
		for i in range(1,int(sys.argv[3]),1):
			upload_time(sys.argv[2])
		end = clock()
		print end - start
main(sys.argv[1])






