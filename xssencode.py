import sublime
import sublime_plugin
__VERSION__ = '1.0.5'


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


class Base16DecodeCommand(XssEncodeCommand):
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


class Base16EncodeCommand(XssEncodeCommand):
    def convert(self, source_txt):
        try:
            import base64
        except:
            return source_txt
        return base64.b16encode(source_txt.encode("utf-8")).decode()


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


class Md516EncodeCommand(XssEncodeCommand):
    def convert(self, source_txt):
        try:
            import hashlib
        except:
            return source_txt
        return hashlib.md5(source_txt.encode("utf-8")).hexdigest()[8:24]


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


class Js16EncodeCommand(XssEncodeCommand):
    def convert(self, source_txt):
        text = ""
        try:
            import binascii
            text += binascii.b2a_hex(source_txt.encode('utf-8')).decode()
            ret = ""
            for i in range(0, len(text), 2):
                ret += "\\x%s" % (text[i:i + 2])
            return ret
        except:
            sublime.error_message("Can not convert to Js16")


class Js16DecodeCommand(XssEncodeCommand):
    def convert(self, source_txt):
        try:
            text = HexStripxCommand(self).convert(source_txt)
            text = HexToStringCommand(self).convert(text)
            return text
        except:
            sublime.error_message("Js16Decode convert failed.")


class AaEncodeCommand(XssEncodeCommand):
    u"""Encode any JavaScript program to Japanese style emoticons (^_^)."""

    def aaencode(self, text):
        import re
        try:
            text = unicode(text)
        except:
            pass
        t = ""
        b = [
            "(c^_^o)",
            "(ﾟΘﾟ)",
            "((o^_^o) - (ﾟΘﾟ))",
            "(o^_^o)",
            "(ﾟｰﾟ)",
            "((ﾟｰﾟ) + (ﾟΘﾟ))",
            "((o^_^o) +(o^_^o))",
            "((ﾟｰﾟ) + (o^_^o))",
            "((ﾟｰﾟ) + (ﾟｰﾟ))",
            "((ﾟｰﾟ) + (ﾟｰﾟ) + (ﾟΘﾟ))",
            "(ﾟДﾟ) .ﾟωﾟﾉ",
            "(ﾟДﾟ) .ﾟΘﾟﾉ",
            "(ﾟДﾟ) ['c']",
            "(ﾟДﾟ) .ﾟｰﾟﾉ",
            "(ﾟДﾟ) .ﾟДﾟﾉ",
            "(ﾟДﾟ) [ﾟΘﾟ]"
        ]
        r = "ﾟωﾟﾉ= /｀ｍ´）ﾉ ~┻━┻   //*´∇｀*/ ['_']; o=(ﾟｰﾟ)  =_=3; c=(ﾟΘﾟ) =(ﾟｰﾟ)-(ﾟｰﾟ); "
        if re.search('ひだまりスケッチ×(365|３５６)\s*来週も見てくださいね[!！]', text):
            r += "X=_=3; "
            r += "\r\n\r\n    X / _ / X < \"来週も見てくださいね!\";\r\n\r\n"

        r += "(ﾟДﾟ) =(ﾟΘﾟ)= (o^_^o)/ (o^_^o);" +\
            "(ﾟДﾟ)={ﾟΘﾟ: '_' ,ﾟωﾟﾉ : ((ﾟωﾟﾉ==3) +'_') [ﾟΘﾟ] " + \
            ",ﾟｰﾟﾉ :(ﾟωﾟﾉ+ '_')[o^_^o -(ﾟΘﾟ)] " +\
            ",ﾟДﾟﾉ:((ﾟｰﾟ==3) +'_')[ﾟｰﾟ] }; (ﾟДﾟ) [ﾟΘﾟ] =((ﾟωﾟﾉ==3) +'_') [c^_^o];" +\
            "(ﾟДﾟ) ['c'] = ((ﾟДﾟ)+'_') [ (ﾟｰﾟ)+(ﾟｰﾟ)-(ﾟΘﾟ) ];" +\
            "(ﾟДﾟ) ['o'] = ((ﾟДﾟ)+'_') [ﾟΘﾟ];" +\
            "(ﾟoﾟ)=(ﾟДﾟ) ['c']+(ﾟДﾟ) ['o']+(ﾟωﾟﾉ +'_')[ﾟΘﾟ]+ ((ﾟωﾟﾉ==3) +'_') [ﾟｰﾟ] + " +\
            "((ﾟДﾟ) +'_') [(ﾟｰﾟ)+(ﾟｰﾟ)]+ ((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+" +\
            "((ﾟｰﾟ==3) +'_') [(ﾟｰﾟ) - (ﾟΘﾟ)]+(ﾟДﾟ) ['c']+" +\
            "((ﾟДﾟ)+'_') [(ﾟｰﾟ)+(ﾟｰﾟ)]+ (ﾟДﾟ) ['o']+" +\
            "((ﾟｰﾟ==3) +'_') [ﾟΘﾟ];(ﾟДﾟ) ['_'] =(o^_^o) [ﾟoﾟ] [ﾟoﾟ];" +\
            "(ﾟεﾟ)=((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+ (ﾟДﾟ) .ﾟДﾟﾉ+" +\
            "((ﾟДﾟ)+'_') [(ﾟｰﾟ) + (ﾟｰﾟ)]+((ﾟｰﾟ==3) +'_') [o^_^o -ﾟΘﾟ]+" +\
            "((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+ (ﾟωﾟﾉ +'_') [ﾟΘﾟ]; " +\
            "(ﾟｰﾟ)+=(ﾟΘﾟ); (ﾟДﾟ)[ﾟεﾟ]='\\\\'; " +\
            "(ﾟДﾟ).ﾟΘﾟﾉ=(ﾟДﾟ+ ﾟｰﾟ)[o^_^o -(ﾟΘﾟ)];" +\
            "(oﾟｰﾟo)=(ﾟωﾟﾉ +'_')[c^_^o];" +\
            "(ﾟДﾟ) [ﾟoﾟ]='\\\"';" +\
            "(ﾟДﾟ) ['_'] ( (ﾟДﾟ) ['_'] (ﾟεﾟ+"
        r += "(ﾟДﾟ)[ﾟoﾟ]+ "
        for i in range(len(text)):
            n = ord(text[i])
            t = "(ﾟДﾟ)[ﾟεﾟ]+"
            if(n <= 127):
                nt = "%o" % n
                for x in range(len(nt)):
                    t += b[int(nt[x])] + "+ "
            else:
                nt = "%04x" % n
                t += "(oﾟｰﾟo)+ "
                for x in range(len(nt)):
                    t += b[int(eval("0x%s" % nt[x]))] + "+ "
            r += t
        r += "(ﾟДﾟ)[ﾟoﾟ]) (ﾟΘﾟ)) ('_');"
        return r

    def convert(self, source_txt):
        try:
            text = self.aaencode(source_txt)
            return text
        except:
            sublime.error_message("aaEncode convert failed.")


class AaDecodeCommand(XssEncodeCommand):
    u"""Encode any JavaScript program to Japanese style emoticons (^_^)."""

    def convert(self, source_txt):
        try:
            evalPreamble = u"(\uFF9F\u0414\uFF9F) ['_'] ( (\uFF9F\u0414\uFF9F) ['_'] ("
            decodePreamble = u"( (\uFF9F\u0414\uFF9F) ['_'] ("
            evalPostamble = u") (\uFF9F\u0398\uFF9F)) ('_');"
            decodePostamble = u") ());"
            text = source_txt.strip()
            if text.rfind(evalPostamble) < 0:
                sublime.error_message("Given code is not encoded as aaencode.")
                return source_txt
            if text.rfind(evalPostamble) != len(text) - len(evalPostamble):
                sublime.error_message("Given code is not encoded as aaencode.")
                return source_txt
            text = text.replace(evalPreamble, decodePreamble).replace(
                evalPostamble, decodePostamble)
            sublime.message_dialog('Decode end. Run the script you will see result.')
            return text
        except:
            sublime.error_message("aaDecode convert failed.")


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
