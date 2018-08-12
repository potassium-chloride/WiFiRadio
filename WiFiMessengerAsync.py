#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
if(len(sys.argv)!=2):
	print("Usage: sudo "+sys.argv[0]+" interface")
	sys.exit(1)

print("Загрузка...")

import os,threading,subprocess,random,scap

def bashExec(q):
	return subprocess.check_output(q,shell=True).decode("UTF-8")

isNeedModeManaged=True

if(bashExec("iwconfig "+sys.argv[1]).count("Mode:Monitor")>0):
	isNeedModeManaged=False
else:
	os.system("ifconfig "+sys.argv[1]+" down && iwconfig "+sys.argv[1]+" mode monitor && ifconfig "+sys.argv[1]+" up")#TODO: kill network processes
	print("Адаптер переведён в режим монитора")

try:
	print(bashExec("iwlist wlp4s0 freq | grep Current").replace("\n","").replace("\t","").replace("  ",""))
except:
	print("Unknown frequency")

keyWord="WF_Radio0.0"

lastId=-1
sentId=-1
sentPak=keyWord.encode("UTF-8")
kwd=keyWord.encode("UTF-8")
N=10
#Format: keyWord+randID+":"+info
debugP=None

scap.init_send_iface(sys.argv[1])

def sv(bts):
	global lastId,sentId,keyWord,sentPak,kwd
	if(bts.count(kwd)>0):
		res="<Сломанный пакет>"
		try:
			res=bts[bts.index(kwd)+len(keyWord):bts.rindex(b'\n')].decode("UTF-8")
		except:
			print("\t\t\t"+res)
		randId=int(res[:res.index(":")])
		if(lastId==randId or sentId==randId):
			return
		lastId=randId
		print("\t\t\t"+res[res.index(":")+1:])

def snifer():
	print("Готов к приёму")
	while True:
		try:
			scap.sniff(iface=sys.argv[1], prn=sv)
		except OSError:
			pass
		except KeyboardInterrupt:
			sys.exit(0)
		except Exception as e:
			print("Error: "+str(e))


sys.stdout.write("Представьтесь: ")
sys.stdout.flush()
username=""
try:
	username=sys.stdin.readline()[:-1]+": "
except KeyboardInterrupt:
	print("Выход")
	sys.exit(0)

t = threading.Thread(target=snifer)
t.daemon = True
t.start()

print("Готов к отправке\n")
while True:
	try:
		s=sys.stdin.readline()
		sentId=random.randrange(0,9999)
		data=keyWord+str(sentId)+":\033[1;33m"+username+"\033[0m"+s+"\n"
		scap.simpleSend(data, iface=sys.argv[1], count=N)
	except KeyboardInterrupt:
		print("Выход")
		if(isNeedModeManaged):
			os.system("ifconfig "+sys.argv[1]+" down && iwconfig "+sys.argv[1]+" mode managed && ifconfig "+sys.argv[1]+" up")
		sys.exit(0)



