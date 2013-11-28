# Copyright (c) 2004-2005 Simplistix Ltd
# Copyright (c) 2001-2003 New Information Paradigms Ltd
#
# This Software is released under the MIT License:
# http://www.opensource.org/licenses/mit-license.html
# See license.txt for more details.

import datetime
import os
import smtplib
import socket

from email.MIMEText import MIMEText
from logging.handlers import SMTPHandler
from logging import Formatter, LogRecord, CRITICAL

now = datetime.datetime.now

class SubjectFormatter(Formatter):
    
    def format(self,record):
        record.message = record.getMessage()
        if self._fmt.find('%(line)') >= 0:
            record.line = record.message.split('\n')[0]
        if self._fmt.find("%(asctime)") >= 0:
            record.asctime = self.formatTime(record, self.datefmt)
        if self._fmt.find("%(hostname)") >= 0:
            record.hostname = socket.gethostname()
        return self._fmt % record.__dict__
    
class MailingLogger(SMTPHandler):

    def __init__(self, mailhost, fromaddr, toaddrs, subject, credentials=None, secure=None, send_empty_entries=False, flood_level=None):
        SMTPHandler.__init__(self, mailhost, fromaddr, toaddrs, subject, credentials=credentials, secure=secure)
        self.subject_formatter = SubjectFormatter(subject)
        self.send_empty_entries = send_empty_entries
        self.flood_level = flood_level
        self.hour = now().hour
        self.sent = 0
        
    def getSubject(self,record):
        return self.subject_formatter.format(record)

    def emit(self,record):
        current_time = now()
        current_hour = current_time.hour
        if current_hour > self.hour:
            self.hour = current_hour
            self.sent = 0
        if self.sent == self.flood_level:
            # send critical error
            record = LogRecord(
                name = 'flood',
                level = CRITICAL,
                pathname = '',
                lineno = 0,
                msg = """Too Many Log Entries
                
More than %s entries have been logged that would have resulted in
emails being sent.

No further emails will be sent for log entries generated between
%s and %i:00:00

Please consult any other configured logs, such as a File Logger,
that may contain important entries that have not been emailed.
""" % (self.sent,current_time.strftime('%H:%M:%S'),current_hour+1),
                args = (),
                exc_info = None)
        if not self.send_empty_entries and not record.msg.strip():
            return
        elif self.sent > self.flood_level:
            # do nothing, we've sent too many emails already
            return
        self.sent += 1

        # actually send the mail
        try:
            import smtplib
            port = self.mailport
            if not port:
                port = smtplib.SMTP_PORT
            smtp = smtplib.SMTP(self.mailhost, port)
            msg = self.format(record)
            email = MIMEText(msg)
            email['Subject']=self.getSubject(record)
            email['From']=self.fromaddr
            email['To']=', '.join(self.toaddrs)
            email['X-Mailer']='MailingLogger'
            if self.username:
                if self.secure is not None:
                    smtp.starttls(*self.secure)
                    smtp.login(self.username, self.password)
            smtp.sendmail(self.fromaddr, self.toaddrs, email.as_string())
            smtp.quit()
        except:
            self.handleError(record)
