import sys
import openpyxl
import os
import socket
import subprocess
import csv
from termcolor import colored

userHostName = ''
directory = ''
findingList = []
vulnDictionary = {}

def recreateConsole():
        global userHostName
        global directory
        username = os.environ['USER']
        hostname = socket.gethostname()
        userHostName = username + '@' + hostname
        directory = os.environ['PWD']

def readCSV():
	print colored('Reading in CSV...', 'green', attrs=['bold'])
	global vulnDictionary
	with open('./reportCMD.csv', 'rb') as csvfile:
		csvRead = csv.reader(csvfile, delimiter=',')
		for row in csvRead:
			id = row[0]
			command = row[1]
			vulnDictionary[id] = command

def vulnSearch(id, ip, port):
	if id in vulnDictionary:
        	port = port.split('/')
		port = port[0]
        	recreateConsole()
        	cmd = vulnDictionary.get(id)
		if cmd.find('IP'):
			cmd = cmd.replace("IP", ip)
		if cmd.find('PORT'):
			cmd = cmd.replace("PORT", port)
		print colored(userHostName, 'red', attrs=['bold']) + ':' + colored(directory, 'blue', attrs=['bold']) + '$ ' + cmd
        	running = subprocess.call(cmd, shell=True)
		waiting = raw_input("Press enter to continue...")

def getFindings(vulnList):
		print colored('Reading Rows...', 'green', attrs=['bold'])
		for row in range(2,vulnList.max_row + 1):
			finding = vulnList['A' + str(row)].value
			if finding in findingList:
				continue
			hostname = vulnList['E' + str(row)].value
			IP = vulnList['F' + str(row)].value
			Port = vulnList['G' + str(row)].value
			print 'Finding: ' + finding + ' Hostname: ' + hostname + ' IP: ' + IP + ' Port: ' + Port
			vulnSearch(finding, IP, Port)
			findingList.append(finding)

def main():
		usageMessage = "Must include path to evidence (Nessus) spreadsheet: sudo ./reportCMD.py spreadsheet.xlsx"
		try:
			wb = openpyxl.load_workbook(sys.argv[1])
			print colored('Nessus Spreadsheet loading...', 'green', attrs=['bold'])

		except:
			print usageMessage
			sys.exit()

		activeSheet = wb.active
		vulnList = wb.get_sheet_by_name("Vuln List")
		readCSV()
		getFindings(vulnList)
main()
