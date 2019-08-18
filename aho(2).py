#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  aho.py
#  
#  Copyright 2017 newbie <newbie@newbie-X451CAP>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  
#  
import ahocorasick
import sys
import getopt
import csv

def help_menu():
	print "-h atau --help menampilkan pesan ini\n"
	print "-d file.txt atau --data=<file.txt> parameter masukan file kunci/kamus\n"
	print "-c file.csv atau --cari=<file.csv>  parameter untuk masukan file dataset\n"
	print "-o file.txt atau --output=<file.txt>  parameter untuk file log\n"

def main(args):
	tmp = []
	warn = []
	war = []
	feat = []
	data_dari_dataset = []
	data_masuk_aho = []
	kunci = ["IP:","P_Src:","Proto:","Alert:"]
	cmd_param = sys.argv[1:] 
	if(len(cmd_param) < 1):
		print "Gunakan %s -h for help" %sys.argv[0]
		sys.exit(1)
	else:
		opt,arg = getopt.getopt(cmd_param, 'hd:c:o:',['help','data=','cari=','output ='])
	for opsi,param in opt:
		if opsi == '-h' or opsi == '--help':
			help_menu()
			sys.exit(0)
		if opsi == '-d' or opsi == '--data':
			file_key = param
		if opsi == '-o' or opsi == '--output':
			file_output= param
		if opsi == '-c' or opsi == '--cari':
			file_dataset= param
		k_len = len(kunci)
	file_log = open(file_output,'w') #create log file
	with open(file_key,'r') as kms: #open key file
		for kmss in kms:
			for bla in range (k_len):
				kmss = kmss.split(kunci[bla])
				kmss = ' '.join(kmss)
			tmp = kmss
			pecah = tmp.split()
			warn.append(pecah[3])
			warn.append(pecah[4])
			del pecah[4]
			del pecah[3]
			#print pecah
			warn= " ".join(warn)
			feat = " ".join(pecah)
			war.append(warn)
			data_masuk_aho.append(feat)
			tmp = []
			warn = []
			feat = []
			
	#aho corrasick implementation with lib
	aho_c = ahocorasick.Automaton()
	for idx, keyy in enumerate(data_masuk_aho):
		aho_c.add_word(keyy,(idx,keyy))
	#end of aho corrasick
			
	with open(file_dataset,'r') as dt: #open dataset file
		dt_csv = csv.reader(dt)
		for dtt in dt_csv:
			#['53', 'TCP', 'Thu Dec  8 14:15:41 2016', ' 1481181341.549447', '49.50.7.43', ' 10.100.115.61', ' 54', ' 20 bytes', '40', '8689', '27873', '16384', '80', '1142', '-A---F', '3525903284', '883024004', '15', '0', '-', '-', '-', '-', '2557', '-----http------', ' j.8...{......E..(!.@.6.l.12.+ads=.P.v4....)..P.............', '']
			data_dari_dataset.append(dtt[4])
			data_dari_dataset.append(dtt[11])
			data_dari_dataset.append(dtt[1])
			data_dari_dataset = " ".join(data_dari_dataset)
			buf = ",".join(dtt)
			if data_dari_dataset in aho_c: #detection start here
				a,b=aho_c.get(data_dari_dataset)
				file_log.write(buf)
				file_log.write("\t")
				file_log.write(war[a])
				file_log.write("\n")
			data_dari_dataset = []
			
	#release all file
	kms.close()
	file_log.close()
	dt.close()

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
