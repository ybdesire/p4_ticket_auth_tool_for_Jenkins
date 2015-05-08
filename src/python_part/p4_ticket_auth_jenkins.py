# !/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import argparse
import logging
import jenkins
import xml.etree.ElementTree as ET
import time
import os
from subprocess import Popen, PIPE, STDOUT
import subprocess
import commands
import socket
import datetime
import httplib
import urllib2

__author__ = "bin.yin@citrix.com"
__application__ = "Jenkins CI P4 Job configuration modification tool"
__version__ = "1.0.0"

LOG = None

class P4TicketAuthMgr:
    def __init__(self, arguments):
        self.arguments = arguments
        self.jci=None   #Jenkins CI connection
        self.cfg_xml_origin = None
        self.cfg_xml_dst = None
        self.p4User = None
        self.p4Passwd = None
        self.p4Port = None

    def get_jenkins_handler(self):
        try:
            self.jci = jenkins.Jenkins(self.arguments.ci_url, self.arguments.ci_username, self.arguments.ci_password)
            self.cfg_xml_origin = self.jci.get_job_config(self.arguments.ci_prj_name)

        except Exception as e:
            LOG.critical("Cannot connect to Jenkins, please check you user name/password/url: {0}".format(e))
            quit_application(-1)
    
    def get_p4_password_from_jenkins(self):
        try:
            p4_ticket_auth_job_cfg_xml_origin = self.jci.get_job_config("P4TicketAuthCredential-" + self.arguments.ci_prj_name)
            root = ET.fromstring(p4_ticket_auth_job_cfg_xml_origin)
            tree = ET.ElementTree(root)
            
            #get parameter
            for scm in root.findall('scm'):
                self.p4User = scm.find('p4User').text
                encry_p4Passwd = scm.find('p4Passwd').text
                self.p4Port = scm.find('p4Port').text
            
            #decrypt password
            self.p4Passwd = subprocess.check_output("java -jar encry.jar -de {0}".format(encry_p4Passwd)).replace("\r\n", "")

                
        except Exception as e:
            LOG.critical("P4TicketAuth job exception: {0}".format(e))
            quit_application(-1)
   
    def get_p4_ticket_from_cmd_output(self, tickets):
        try:
            for ticket_item in tickets.split("\n"):
                if(ticket_item != ""):
                    #get server
                    input_server = self.p4Port.split(":")[0]
                    input_server_ip = socket.gethostbyname(input_server)
                    
                    input_server_port = self.p4Port
                    input_server_ip_port = input_server_ip + ":" + self.p4Port.split(":")[1]
                    ticket_item_port = ticket_item.split(" ")[0]
                    
                    #get user
                    ticket_item_user = ticket_item.split(" ")[1].replace("(", "").replace(")", "")
                    
                    if( ((ticket_item_port.split(":")[1]==input_server_port.split(":")[1]) or (ticket_item_port.split(":")[1]==input_server_ip_port.split(":")[1])) and (ticket_item_user==self.p4User) ):
                        return  ticket_item.split(" ")[2] 
                    
        except Exception as e:
            LOG.critical("P4 tickets parse exception: {0}".format(e))
    
    def get_p4_ticket_encry(self):
        try:
            cmd_set_p4_port = "p4 set P4PORT={0}".format(self.p4Port)
            cmd_set_p4_user = "p4 set P4USER={0}".format(self.p4User)
            os.system(cmd_set_p4_port)
            os.system(cmd_set_p4_user)
            
            p_cmd_p4_login = Popen(["C:\Program Files\Perforce\p4.exe", "login"], stdout=PIPE, stdin=PIPE)   
            p_cmd_p4_login.communicate(input="{0}".format(self.p4Passwd))
            
            #p_ticket = Popen(["C:\Program Files\Perforce\p4.exe", "tickets"], stdout=PIPE, stdin=PIPE)   
            #tickets = p_ticket.stdout.read()
            tickets = subprocess.check_output("p4 tickets")
            
            ticket = self.get_p4_ticket_from_cmd_output(tickets).replace("\r", "")
            encry_ticket = subprocess.check_output("java -jar encry.jar -en {0}".format(ticket))
            #print(password_encrypt)
            return encry_ticket
            
        except Exception as e:
            LOG.critical("P4 exception: {0}".format(e))

    def set_job_cfg_xml(self, ency_ticket):
        try:
            root = ET.fromstring(self.cfg_xml_origin)
            tree = ET.ElementTree(root)
            
            #set parameter
            for scm in root.findall('scm'):
                if self.p4Passwd:
                    scm.find('p4Passwd').text = ency_ticket
            
            self.cfg_xml_dst = ET.tostring(root, encoding='utf-8', method='xml')
            self.cfg_xml_dst = "<?xml version='1.0' encoding='UTF-8'?>" + "\n" + self.cfg_xml_dst 
        except Exception as e:
            LOG.critical("ElementTree exception: {0}".format(e))
            quit_application(-1)

    def reset_ci_ticket(self, ency_ticket):
        try:
            self.set_job_cfg_xml(ency_ticket)
            self.jci.reconfig_job(self.arguments.ci_prj_name, self.cfg_xml_dst)
        except Exception as e:
            LOG.critical("Set Jenkins exception: {0}".format(e))
                         
    def keepCITicketAuth(self):
        try:
            self.get_jenkins_handler()
            self.get_p4_password_from_jenkins()
            encry_ticket = self.get_p4_ticket_encry()
            self.reset_ci_ticket(encry_ticket)
            print("{0}--keeping ticket auth of project '{1}'".format(datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d %H:%M:%S'), self.arguments.ci_prj_name))
        except Exception as e:
            LOG.critical("")
            
                
def log_initialize(arguments):
    try:
        global LOG  
        LOG = logging.getLogger(__name__)
        LOG.setLevel(logging.INFO)
        formatter = logging.Formatter("[%(levelname)s]: %(message)s")
        if arguments.log:
            file_handler = logging.FileHandler(filename = arguments.log, mode = 'w', encoding = "utf_8_sig", delay = False)
            file_handler.setFormatter(formatter)
            LOG.addHandler(file_handler)
        stream_handler = logging.StreamHandler(stream = sys.stdout)
        stream_handler.setFormatter(formatter)
        LOG.addHandler(stream_handler)
    except Exception as e:
        print("[CRITICAL]: An error occurred when initializing logging: {exception}".format(exception = e))
        quit_application(-1)


def parse_arguments():
    arg_parser = argparse.ArgumentParser(description = "Jenkins CI P4 ticket auth keep tool")
    arg_parser.add_argument("ci_url", help = "Jenkins URL, such as 'http://beacon-test-ci.eng.citrite.net:8080/'")
    arg_parser.add_argument("ci_username", help = "Jenkins username")
    arg_parser.add_argument("ci_password", help = "Jenkins password")
    arg_parser.add_argument("ci_prj_name", help= "the project name at Jenkins")
    arg_parser.add_argument("-l", "--log", metavar = "log.txt", help = "specify the log file")
    return arg_parser.parse_args()


def quit_application(status):  
    if(status==-1):
        LOG.info("{application} exited abnormally".format(application=__application__))
    else:
        LOG.info("{application} exited normally".format(application=__application__))
    sys.exit(status)


def main():
    arguments= parse_arguments()
    log_initialize(arguments)    
    ticketAuth = P4TicketAuthMgr(arguments)
    ticketAuth.keepCITicketAuth()
    return 0


if __name__=="__main__":
    result = main()
    quit_application(result)

