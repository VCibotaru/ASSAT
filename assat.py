__author__ = 'viktorchibotaru'

import argparse
import os
import re

class File:
    """Class for convenient storage of file name and content. Is used in static analysis and outputting"""
    def __init__(self, content, path):
        self.content = content
        self.path = path


class ConstString:
    """Class for holding (flag, help) pairs used for setting work modes in Menu class"""
    def __init__(self, _flag, _help):
        self.flag = _flag
        self.help = _help


class Const:
    """Just a bunch of constant values moved for convenience into a class, just like enums in C++"""
    SXML = ConstString('sxml', 'list all occurrences of getSharedPreferences() and setSharedPreferences()')
    SKEY = ConstString('skey', 'list all occurrences of KeyChain/KeyStore objects')
    SCRYPT = ConstString('scrypt', 'list all occurrences of cryptographic methods')
    DXML = ConstString('dxml', 'get the xml file from device')
    DBD = ConstString('dbd', 'list all schemes and tables in all found databases')
    PATH = ConstString('path', 'path to the folder, containing the decompiled java code')
    DESC = 'Android Secure Storage Analysis Tool'
    STATIC_FLAGS = [SXML.flag, SKEY.flag, SCRYPT.flag]
    DYNAMIC_FLAGS = [DXML.flag, DBD.flag]

    ERR_NO_WORK_MODE = 'No work mode specified! Please run the script with --help flag to get help'
    ERR_NO_PATH = 'Please specify the path to Java decompiled code directory via --path flag'

    PREFS = 'sharedpreferences'

class Logger:
    """
    Logger class is used for outputting. Maybe the app will support more complex logging
    features in future, so I decided to create a dedicated class for them.
    Now all it does is simple print(text) and exception(text) in case of some error.
    """
    @staticmethod
    def normal_output(text):
        print(text)

    @staticmethod
    def error_output(text):
        raise ValueError(text)

    @staticmethod
    def line_output(line, number, file):
        print('Found interesting line at %s:%d\n%s') % (file, number, line)


class Menu:
    """Menu class is used for selecting the tasks to be done"""
    def __init__(self):
        self.args = {}

    """parseFlags() does the flags parsing and stores the results into self.args dictionary"""
    def parse_flags(self):
        parser = argparse.ArgumentParser(description=Const.DESC)
        parser.add_argument('--' + Const.SXML.flag, action='store_true', help=Const.SXML.help)
        parser.add_argument('--' + Const.SKEY.flag, action='store_true', help=Const.SKEY.help)
        parser.add_argument('--' + Const.SCRYPT.flag, action='store_true', help=Const.SCRYPT.help)
        parser.add_argument('--' + Const.DXML.flag, action='store_true', help=Const.DXML.help)
        parser.add_argument('--' + Const.DBD.flag, action='store_true', help=Const.DBD.help)
        parser.add_argument('--' + Const.PATH.flag, help=Const.PATH.help)
        self.args = vars(parser.parse_args())

    """
    work() checks that exactly one flag was specified, and in case of static analysis mode,
    that the path to the java code was given. After this check it creates an object of the
    specific class and calls it`s analyze() method.
    """
    def work(self):
        values = list(self.args.values())
        if values.count(True) != 1:
            Logger.error_output(Const.ERR_NO_WORK_MODE)
        for key in self.args.keys():
            if self.args[key] is True:
                break
        if key in Const.STATIC_FLAGS:
            if self.args[Const.PATH.flag] is None:
                Logger.error_output(Const.ERR_NO_PATH)
            java = Java(self.args['path'])
            st_analyzer = XMLStatic(java)
            st_analyzer.analyze()
        elif key in Const.DYNAMIC_FLAGS:
            dynamic = Dynamic()
            dynamic.analyze()


class Java:
    """
    Java class is created for convenient work with the program representation
    on hard disk (be it decompiled text or byte code). Now it supports only the
    text variant, but it`s in my plans to expand its features.

    This class` main task is to recursively scan the given folder for all code files
    and to return their contents one by one. This is done in two steps, explained beyond.
    """
    def __init__(self, path):
        self.path = path

    """Java.files() is a simple generator that returns all the files in given directory  one at a time"""
    def files(self):
        for dir_path, dir_names, file_names in os.walk(self.path):
            for filename in file_names:
                yield os.path.join(dir_path, filename)

    """Java.get_file_content() returns the content of the selected file"""
    def get_file_content(self, filepath):
        file = open(filepath)
        return file.readlines()


class Static(object):
    """
    The base class for all static analyzers.
    """
    def __init__(self, java):
        self.java = java

    """
    get_next_file() is a generator that returns one by one File objects,
    containing  the file path and the code in file.
    """
    def get_next_file(self):
        for filename in self.java.files():
            if filename.endswith('java'):
                yield File(self.java.get_file_content(filename), filename)


class XMLStatic(Static):
    """
    Does the static xml analysis in analyze method(). Now it`s simple pattern matching, maybe i will
    figure out something smarter. Also it would be great to wrap up the output nicely (a table or similar).
    """
    def __init__(self, java):
        super(self.__class__, self).__init__(java)

    def analyze(self):
        for file in self.get_next_file():
            for num, line in enumerate(file.content):
                if re.search(Const.PREFS, line, re.IGNORECASE):
                    Logger.line_output(line, num, file.path)


class KeyStatic(Static):
    def __init__(self, java):
        super().__init__(java)

    def analyze(self):
        for file in self.get_next_file():
            print(file.path + '\n' + file.content)


class Dynamic:
    def __init__(self):
        pass

    def analyze(self):
        pass

menu = Menu()
menu.parse_flags()
menu.work()