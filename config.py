import ConfigParser

class Config:
    ''' Read in the config and set up the vars with the correct type.
    '''
    def __init__(self, configfile, name):
        c = ConfigParser.ConfigParser()
        c.read(configfile)
        self.database = c.get(name, 'database')
        self.mailhost = c.get(name, 'mailhost')
        self.adminemail = c.get(name, 'adminemail')
        self.url = c.get(name, 'url')

