import sublime
import sublime_plugin
__VERSION__ = '1.0.2.1'


class XssEncodeCommand(sublime_plugin.TextCommand):
    def run(self, edit):
        for region in self.view.sel():
            if region.empty():
                region = sublime.Region(0, self.view.size())
            text = self.view.substr(region)
            replacement = self.convert(text)
            self.view.replace(edit, region, replacement)

    def convert(self, source_txt):
        return source_txt


class HtmlUnescapeCommand(XssEncodeCommand):
    def convert(self, source_txt):
        try:
            from html.parser import HTMLParser
        except:
            from HTMLParser import HTMLParser
        return HTMLParser().unescape(source_txt)


class HtmlEscapeCommand(XssEncodeCommand):
    def convert(self, source_txt):
        try:
            import cgi
        except:
            return source_txt
        return cgi.escape(source_txt)


class Base64EncodeCommand(XssEncodeCommand):
    def convert(self, source_txt):
        try:
            import base64
        except:
            return source_txt
        return base64.b64encode(source_txt.encode("utf-8")).decode()


class Base64DecodeCommand(XssEncodeCommand):
    def convert(self, source_txt):
        try:
            import base64
        except:
            return source_txt
        try:
            return base64.b64decode(source_txt).decode('utf-8')
        except:
            import binascii
            hexstr = binascii.b2a_hex(base64.b64decode(source_txt))
            ret_str = ''
            for i in range(0, len(hexstr), 2):
                ret_str += "\\x%c%c" % (((hexstr[i]), (hexstr[i + 1])))
            return ret_str


class Base32EncodeCommand(XssEncodeCommand):
    def convert(self, source_txt):
        try:
            import base64
        except:
            return source_txt
        return base64.b32encode(source_txt.encode("utf-8")).decode()


class Base32DecodeCommand(XssEncodeCommand):
    def convert(self, source_txt):
        try:
            import base64
        except:
            return source_txt
        try:
            return base64.b32decode(source_txt).decode('utf-8')
        except:
            import binascii
            hexstr = binascii.b2a_hex(base64.b32decode(source_txt))
            ret_str = ''
            for i in range(0, len(hexstr), 2):
                ret_str += "\\x%c%c" % (((hexstr[i]), (hexstr[i + 1])))
            return ret_str


class Base16EncodeCommand(XssEncodeCommand):
    def convert(self, source_txt):
        try:
            import base64
        except:
            return source_txt
        try:
            return base64.b16decode(source_txt).decode('utf-8')
        except:
            import binascii
            hexstr = binascii.b2a_hex(base64.b16decode(source_txt))
            ret_str = ''
            for i in range(0, len(hexstr), 2):
                ret_str += "\\x%c%c" % (((hexstr[i]), (hexstr[i + 1])))
            return ret_str


class Base16DecodeCommand(XssEncodeCommand):
    def convert(self, source_txt):
        try:
            import base64
        except:
            return source_txt
        return base64.b16decode(source_txt).decode('utf-8')


class UrlEncodeCommand(XssEncodeCommand):
    def convert(self, source_txt):
        try:
            from urllib.parse import quote
        except:
            from urllib import quote
        return quote(source_txt)


class UrlDecodeCommand(XssEncodeCommand):
    def convert(self, source_txt):
        try:
            from urllib.parse import unquote
        except:
            from urllib import unquote
        return unquote(source_txt)


class Md5EncodeCommand(XssEncodeCommand):
    def convert(self, source_txt):
        try:
            import hashlib
        except:
            return source_txt
        return hashlib.md5(source_txt.encode("utf-8")).hexdigest()


class Sha1EncodeCommand(XssEncodeCommand):
    def convert(self, source_txt):
        try:
            import hashlib
        except:
            return source_txt
        return hashlib.sha1(source_txt.encode("utf-8")).hexdigest()


class Sha256EncodeCommand(XssEncodeCommand):
    def convert(self, source_txt):
        try:
            import hashlib
        except:
            return source_txt
        return hashlib.sha256(source_txt.encode("utf-8")).hexdigest()


class Sha512EncodeCommand(XssEncodeCommand):
    def convert(self, source_txt):
        try:
            import hashlib
        except:
            return source_txt
        return hashlib.sha512(source_txt.encode("utf-8")).hexdigest()


class Sha224EncodeCommand(XssEncodeCommand):
    def convert(self, source_txt):
        try:
            import hashlib
        except:
            return source_txt
        return hashlib.sha224(source_txt.encode("utf-8")).hexdigest()


class Sha384EncodeCommand(XssEncodeCommand):
    def convert(self, source_txt):
        try:
            import hashlib
        except:
            return source_txt
        return hashlib.sha384(source_txt.encode("utf-8")).hexdigest()


class Html10EncodeCommand(XssEncodeCommand):
    def convert(self, source_txt):
        text = ""
        try:
            for i in range(len(source_txt)):
                text += "&#%s;" % ord(source_txt[i])
            return text
        except:
            sublime.error_message("Can not convert to HTML10 Entities")


class Html16EncodeCommand(XssEncodeCommand):
    def convert(self, source_txt):
        text = ""
        try:
            for i in range(len(source_txt)):
                text += "&#x%x;" % ord(source_txt[i])
            return text
        except:
            sublime.error_message("Can not convert to HTML16 Entities")


class StringFromCharCodeCommand(XssEncodeCommand):
    def convert(self, source_txt):
        text = "String.fromCharCode("
        try:
            for i in range(len(source_txt)):
                text += "%s," % ord(source_txt[i])
            text = text[:-1] + ")"
            return text
        except:
            sublime.error_message("Can not convert to String.fromCharCode")


class MysqlCharCommand(XssEncodeCommand):
    def convert(self, source_txt):
        text = "CHAR("
        try:
            for i in range(len(source_txt)):
                text += "%s," % str(ord(source_txt[i]))
            text = text[:-1] + ")"
            return text
        except:
            sublime.error_message("Can not convert to MysqlChar")


class OracleChrCommand(XssEncodeCommand):
    def convert(self, source_txt):
        text = ""
        try:
            for i in range(len(source_txt)):
                text += "CHR(%s)||" % str(ord(source_txt[i]))
            text = text[:-2]
            return text
        except:
            sublime.error_message("Can not convert to OracleChr")


class OracleUnchrCommand(XssEncodeCommand):
    def convert(self, source_txt):
        import re

        def unescape(txt):
            l = re.findall(r'CHR\((\d+?)\)', txt, re.I)
            tmp = ""
            for x in l:
                tmp += chr(int(x))
            return tmp

        try:
            splitchr = "\|"
            chrlists = re.findall(
                r'CHR\(\d+?\)%s{0,2}' % splitchr,
                source_txt, re.M | re.I)
            chrstrs = []
            temp = ""
            for item in range(len(chrlists)):
                temp += chrlists[item]
                if not re.search(splitchr, chrlists[item]):
                    chrstrs.append(temp)
                    temp = ""
            chrstrs = sorted(chrstrs, key=lambda x: len(x))
            chrstrs.reverse()
            for item in chrstrs:
                source_txt = source_txt.replace(item, '"%s"' % unescape(item))
            return source_txt
        except:
            sublime.error_message("Can not convert to OracleUnchr")


class PhpChrCommand(XssEncodeCommand):
    def convert(self, source_txt):
        text = ""
        try:
            for i in range(len(source_txt)):
                text += "CHR(%s)." % str(ord(source_txt[i]))
            text = text[:-1]
            return text
        except:
            sublime.error_message("Can not convert to PhpChr")


class PhpUnchrCommand(XssEncodeCommand):
    def convert(self, source_txt):
        import re

        def unescape(txt):
            l = re.findall(r'CHR\((\d+?)\)', txt, re.I)
            tmp = ""
            for x in l:
                tmp += chr(int(x))
            return tmp

        try:
            splitchr = "\."
            chrlists = re.findall(
                r'CHR\(\d+?\)%s{0,1}' % splitchr,
                source_txt, re.M | re.I)
            chrstrs = []
            temp = ""
            for item in range(len(chrlists)):
                temp += chrlists[item]
                if not re.search(splitchr, chrlists[item]):
                    chrstrs.append(temp)
                    temp = ""
            chrstrs = sorted(chrstrs, key=lambda x: len(x))
            chrstrs.reverse()
            for item in chrstrs:
                source_txt = source_txt.replace(item, '"%s"' % unescape(item))
            return source_txt
        except:
            sublime.error_message("Can not convert to PhpUnhr")


class StringToHexCommand(XssEncodeCommand):
    def convert(self, source_txt):
        text = ""
        try:
            import binascii
            text += binascii.b2a_hex(source_txt.encode('utf-8')).decode()
            return text
        except:
            sublime.error_message("Can not convert to StringToHex")


class HexToStringCommand(XssEncodeCommand):
    def convert(self, source_txt):
        text = ""
        try:
            if source_txt.startswith('0x'):
                source_txt = source_txt[2:]
            import binascii
            text += binascii.a2b_hex(source_txt).decode()
            return text
        except:
            sublime.error_message("Can not convert to HexToString")


class UnicodeDecodeCommand(XssEncodeCommand):
    def convert(self, source_txt):
        text = ""
        try:
            text = source_txt.encode().decode('unicode_escape')
            return text
        except:
            sublime.error_message("Can not convert to UnicodeDecode")


class UnicodeEncodeCommand(XssEncodeCommand):
    def convert(self, source_txt):
        text = ""
        try:
            text = source_txt.encode('unicode_escape').decode()
            return text
        except:
            sublime.error_message("Can not convert to UnicodeEncode")


class ZipDecodeCommand(XssEncodeCommand):

    def convert(self, source_txt):
        text = ""
        try:
            import zlib
            import codecs
            text = zlib.decompress(codecs.escape_decode(source_txt)[0]).decode()
            return text
        except:
            sublime.error_message("Unzip failed.")


class ZipEncodeCommand(XssEncodeCommand):

    def convert(self, source_txt):
        text = ""
        try:
            import zlib
            import codecs
            text = zlib.compress(source_txt.encode())
            return codecs.escape_encode(text)[0].decode()
        except:
            sublime.error_message("Zip failed.")


class Rot13EncodeCommand(XssEncodeCommand):

    def convert(self, source_txt):
        text = ""
        try:
            import codecs
            text = codecs.encode(source_txt, "rot-13")
            return text
        except:
            sublime.error_message("Rot13 convert failed.")


class Rot13DecodeCommand(Rot13EncodeCommand):
    pass


class HexStripxCommand(XssEncodeCommand):
    def convert(self, source_txt):
        try:
            return source_txt.replace('\\x', '')
        except:
            sublime.error_message("HexStrip \\X failed.")


class TestEncodeCommand(XssEncodeCommand, sublime_plugin.WindowCommand):

    def convert(self, source_txt):
        self.source_txt = source_txt
        self.convert_txt = source_txt
        self.view.window().show_input_panel(
            'Input key here:', '', self.on_done, self.on_change, None)
        return self.convert_txt

    def on_done(self, m):
        sublime.status_message(m)

    def on_change(self, m):
        sublime.status_message("Press ESC to calcel, key: %s" % m)


class TestDecodeCommand(XssEncodeCommand, sublime_plugin.WindowCommand):

    def convert(self, source_txt):
        self.source_txt = source_txt
        self.convert_txt = source_txt
        self.view.window().show_input_panel(
            'Input key here:', '',
            self.on_done, self.on_change, None)
        return self.convert_txt

    def on_done(self, m):
        sublime.status_message(m)

    def on_change(self, m):
        sublime.status_message("Press ESC to calcel, key: %s" % m)
