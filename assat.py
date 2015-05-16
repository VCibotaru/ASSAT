__author__ = 'viktorchibotaru'

import argparse
import os
import re


class File:
    """Class for convenient storage of file name and content. Is used in static analysis and outputting"""
    def __init__(self, content, path):
        self.content = content
        self.path = path
        self.data = None  # the analysis data for the file


class ConstString:
    """Class for holding (flag, help) pairs used for setting work modes in Menu class"""
    def __init__(self, flag, help):
        self.flag = flag
        self.help = help


class Const:
    """Just a bunch of constant values moved for convenience into a class, just like enums in C++"""
    SXML = ConstString('sxml', 'list all occurrences of sharedPreferences methods and objects')
    SKEY = ConstString('skey', 'list all occurrences of KeyChain/KeyStore objects')
    SCRYPT = ConstString('scrypt', 'list all occurrences of cryptographic methods')
    SFIND = ConstString('sfind', 'list all occurrences of given pattern')
    DXML = ConstString('dxml', 'get the xml file from device')
    DBD = ConstString('dbd', 'list all schemes and tables in all found databases')
    PATH = ConstString('path', 'path to the folder, containing the decompiled java code used for static analysis')
    PATTERN = ConstString('pattern', 'the pattern to search used in sfind')
    NOCOLOR = ConstString('nocolor', 'use this flag to disable color output (use this when printing to file')
    DESC = 'Android Secure Storage Analysis Tool'
    STATIC_FLAGS = [SXML.flag, SKEY.flag, SCRYPT.flag, SFIND.flag]
    DYNAMIC_FLAGS = [DXML.flag, DBD.flag]

    ERR_NO_WORK_MODE = 'Zero or more than one work modes specified! Please run the script with --help flag to get help'
    ERR_NO_PATH = 'Please specify the path to Java decompiled code directory via --path flag'
    ERR_NO_PATTERN = 'Please specify the pattern to match via --pattern flag'
    GET_REGEXP = r'pref.*get(Int|Boolean|Float|Long|String)'
    SET_REGEXP = r'pref.*put(Int|Boolean|Float|Long|String)'
    PREFS_REGEXP = r'sharedPreferences'

    KEY_REGEXP = r'KeyChain|KeyStore'

    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'

    HEADER = 'Scan results'
    NO_RES = 'No results found'


class Data:
    """
    Data class is used for storing the output data for all files in a convenient manner.
    It also does the necessary formatting, depending on task that was done.
    Data.header              - The message that will be printed first if any results are found
    Data.files               - List of files to be printed. One object corresponds to one file.
    Data.no_results_header   - The message that will be printed in case that no results are found
    """
    def __init__(self):
        self.header = Const.GREEN + Const.HEADER + Const.ENDC
        self.files = []
        self.no_results_header = Const.RED + Const.NO_RES + Const.ENDC

    def append_file(self, file):
        self.files.append(file)

    """get_data() returns the stored data with the right header"""
    def get_data(self):
        s = ''
        for f in self.files:
            tmp = f.data.get_string()
            if len(tmp):
                s += '%s%s%s\n%s' % (Const.GREEN, f.path, Const.ENDC, tmp)
        if len(s) > 0:
            s = self.header + '\n' + s
        else:
            s = self.no_results_header
        return s


class XMLFileData:
    """
    Does the data formatting in a specific manner for XML scan results.
    """
    def __init__(self, getters, setters, rest):
        self.keys = ['Getters', 'Setters', 'Rest']
        self.data = {self.keys[0]: getters[:], self.keys[1]: setters[:], self.keys[2]: rest[:]}

    """get_string() returns the stored data in a pretty formatted manner"""
    def get_string(self):
        s = ''
        for key in self.keys:
            if len(self.data[key]) > 0:
                s += '\t%s%s%s\n\t\t' % (Const.RED, key, Const.ENDC)
                s += '\t\t'.join(self.data[key])
        return s


class KeyFileData:
    """
    Does the data formatting in a specific manner for XML scan results.
    """
    def __init__(self, strings):
        self.strings = strings

    """get_string() returns the stored data in a pretty formatted manner"""
    def get_string(self):
        s = ''
        for str in self.strings:
            s += '\t' + str
        return s


class Logger:
    """
    Logger class is used for outputting. Maybe the app will support more complex logging
    features in future, so I decided to create a dedicated class for them.
    Now all it does is simple print(text) and exception(text) in case of some error.
    """
    @staticmethod
    def normal_output(text):
        print(text)

    """
    If the app encounters an error, this method is used. Basically it only raises an error and prints it with red color
    """
    @staticmethod
    def error_output(text):
        raise ValueError(Const.RED + text + Const.ENDC)

    @staticmethod
    def line_output(line, number, file):
        print('Found interesting line at %s%s%s:%d\n%s%s%s' % (Const.GREEN, file.path, Const.ENDC, number, Const.RED, line, Const.ENDC))

    """ output_data() outputs the data from Data object"""
    @staticmethod
    def output_data(data):
        print(data.get_data())


class Menu:
    """Menu class is used for selecting the tasks to be done"""
    def __init__(self):
        self.args = {}

    """parseFlags() does the flags parsing and stores the results into self.args dictionary"""
    def parse_flags(self):
        parser = argparse.ArgumentParser(description=Const.DESC)
        parser.add_argument('--' + Const.SXML.flag, action='store_true', help=Const.SXML.help)
        parser.add_argument('--' + Const.SKEY.flag, action='store_true', help=Const.SKEY.help)
        #parser.add_argument('--' + Const.SCRYPT.flag, action='store_true', help=Const.SCRYPT.help)
        parser.add_argument('--' + Const.SFIND.flag, action='store_true', help=Const.SFIND.help)
        parser.add_argument('--' + Const.PATTERN.flag, help=Const.PATTERN.help)
        parser.add_argument('--' + Const.DXML.flag, action='store_true', help=Const.DXML.help)
        parser.add_argument('--' + Const.DBD.flag, action='store_true', help=Const.DBD.help)
        parser.add_argument('--' + Const.PATH.flag, help=Const.PATH.help)
        parser.add_argument('--' + Const.NOCOLOR.flag, action='store_true', help=Const.NOCOLOR.help)

        self.args = vars(parser.parse_args())

    """
    work() checks that exactly one flag was specified, and in case of static analysis mode,
    that the path to the java code was given. After this check it creates an object of the
    specific class and calls it`s analyze() method.
    """
    def work(self):
        if self.args[Const.NOCOLOR.flag]:
            Const.GREEN = ''
            Const.RED = ''
            Const.YELLOW = ''
            Const.ENDC = ''
            self.args[Const.NOCOLOR.flag] = False
        values = list(self.args.values())
        if values.count(True) != 1:
            Logger.error_output(Const.ERR_NO_WORK_MODE)
        for key in self.args.keys():
            if self.args[key] is True:
                break
        if key in Const.STATIC_FLAGS:
            if self.args[Const.PATH.flag] is None:
                Logger.error_output(Const.ERR_NO_PATH)
            java = Java(self.args[Const.PATH.flag])
            if key == Const.SXML.flag:
                st_analyzer = XMLStatic(java)
            elif key == Const.SFIND.flag:
                if self.args[Const.PATTERN.flag] is None:
                    Logger.error_output(Const.ERR_NO_PATTERN)
                st_analyzer = FinderStatic(java, self.args[Const.PATTERN.flag])
            else:
                st_analyzer = KeyStatic(java)
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
        data = Data()
        setters = []
        getters = []
        rest = []
        set_re = re.compile(Const.SET_REGEXP, re.IGNORECASE)
        get_re = re.compile(Const.GET_REGEXP, re.IGNORECASE)
        rest_re = re.compile(Const.PREFS_REGEXP, re.IGNORECASE)
        for file in self.get_next_file():
            for num, line in enumerate(file.content):
                s = '%5d : %s\n' % (num, line.strip())
                if re.search(get_re, line):
                    getters.append(s)
                elif re.search(set_re, line):
                    setters.append(s)
                elif re.search(rest_re, line):
                    rest.append(s)
            file.data = XMLFileData(getters, setters, rest)
            data.append_file(file)
            setters[:] = []
            getters[:] = []
            rest[:] = []
        Logger.output_data(data)


class FinderStatic(Static):
    """
    Does the pattern matching with all the strings in all files.
    """
    def __init__(self, java, pattern):
        super(self.__class__, self).__init__(java)
        self.pattern = pattern

    def analyze(self):
        r = re.compile(self.pattern, re.IGNORECASE)
        data = Data()
        tmp = []
        for file in self.get_next_file():
            for num, line in enumerate(file.content):
                if re.search(r, line):
                    tmp.append('%5d : %s\n' % (num, line.strip()))
            file.data = KeyFileData(tmp)
            data.append_file(file)
        Logger.output_data(data)


class KeyStatic(Static):
    def __init__(self, java):
        super(self.__class__, self).__init__(java)

    def analyze(self):
        r = re.compile(Const.KEY_REGEXP, re.IGNORECASE)
        data = Data()
        for file in self.get_next_file():
            tmp = []
            for num, line in enumerate(file.content):
                if re.search(r, line):
                    tmp.append('%5d : %s\n' % (num, line.strip()))
            file.data = KeyFileData(tmp)
            data.append_file(file)
        Logger.output_data(data)


class Dynamic:
    def __init__(self):
        pass

    def analyze(self):
        pass

menu = Menu()
menu.parse_flags()
menu.work()