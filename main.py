import yaml
import base64
import json
import re
import uuid
import random
import requests
from pyDes import des, CBC, PAD_PKCS5
from requests_toolbelt import MultipartEncoder
from datetime import datetime, timezone, timedelta
from Crypto.Cipher import AES
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class Utils:
    def __init__(self):
        pass

    # 获取当前北京时间
    @staticmethod
    def getAsiaTime():
        utc_dt = datetime.utcnow().replace(tzinfo=timezone.utc)
        asia_dt = utc_dt.astimezone(timezone(timedelta(hours=8)))
        return asia_dt.strftime('%H:%M:%S')

    # 获取当前北京日期
    @staticmethod
    def getAsiaDate():
        utc_dt = datetime.utcnow().replace(tzinfo=timezone.utc)
        asia_dt = utc_dt.astimezone(timezone(timedelta(hours=8)))
        return asia_dt.strftime('%Y-%m-%d')

    # 获取指定长度的随机字符
    @staticmethod
    def randString(length):
        baseString = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"
        data = ''
        for i in range(length):
            data += baseString[random.randint(0, len(baseString) - 1)]
        return data

    @staticmethod
    def getYmlConfig(yaml_file='./login/system.yml'):
        file = open(yaml_file, 'r', encoding="utf-8")
        file_data = file.read()
        file.close()
        config = yaml.load(file_data, Loader=yaml.FullLoader)
        return dict(config)

    # aes加密的实现
    @staticmethod
    def encryptAES(password, key):
        randStrLen = 64
        randIvLen = 16
        ranStr = Utils.randString(randStrLen)
        ivStr = Utils.randString(randIvLen)
        aes = AES.new(bytes(key, encoding='utf-8'), AES.MODE_CBC, bytes(ivStr, encoding="utf8"))
        data = ranStr + password

        text_length = len(data)
        amount_to_pad = AES.block_size - (text_length % AES.block_size)
        if amount_to_pad == 0:
            amount_to_pad = AES.block_size
        pad = chr(amount_to_pad)
        data = data + pad * amount_to_pad

        text = aes.encrypt(bytes(data, encoding='utf-8'))
        text = base64.encodebytes(text)
        text = text.decode('utf-8').strip()
        return text


class iapLogin:
    # 初始化iap登陆类
    def __init__(self, username, password, login_url, host, session):
        self.username = username
        self.password = password
        self.login_url = login_url
        self.host = host
        self.session = session
        self.ltInfo = None
        self.count = 0

    # 判断是否需要验证码
    def getNeedCaptchaUrl(self):
        data = self.session.post(f'{self.host}iap/checkNeedCaptcha?username={self.username}', data=json.dumps({}),
                                 verify=False).json()
        return data['needCaptcha']

    def login(self):
        params = {}
        self.ltInfo = self.session.post(f'{self.host}iap/security/lt', data=json.dumps({})).json()
        params['lt'] = self.ltInfo['result']['_lt']
        params['rememberMe'] = 'false'
        params['dllt'] = ''
        params['mobile'] = ''
        params['username'] = self.username
        params['password'] = self.password
        needCaptcha = self.getNeedCaptchaUrl()
        if needCaptcha:
            imgUrl = f'{self.host}iap/generateCaptcha?ltId={self.ltInfo["result"]["_lt"]}'
            code = Utils.getCodeFromImg(self.session, imgUrl)
            params['captcha'] = code
        else:
            params['captcha'] = ''
        data = self.session.post(f'{self.host}iap/doLogin', params=params, verify=False, allow_redirects=False)
        if data.status_code == 302:
            data = self.session.post(data.headers['Location'], verify=False)
            return self.session.cookies
        else:
            data = data.json()
            self.count += 1
            if data['resultCode'] == 'CAPTCHA_NOTMATCH':
                if self.count < 10:
                    self.login()
                else:
                    raise Exception('验证码错误超过10次，请检查')
            elif data['resultCode'] == 'FAIL_UPNOTMATCH':
                raise Exception('用户名密码不匹配，请检查')
            else:
                raise Exception(f'登陆出错，状态码：{data["resultCode"]}，请联系开发者修复...')


class TodayLoginService:
    # 初始化本地登录类
    def __init__(self, userInfo):
        if None == userInfo['username'] or '' == userInfo['username'] or None == userInfo['password'] or '' == userInfo[
            'password'] or None == userInfo['schoolName'] or '' == userInfo['schoolName']:
            raise Exception('初始化类失败，请键入完整的参数（用户名，密码，学校名称）')
        self.username = userInfo['username']
        self.password = userInfo['password']
        self.schoolName = userInfo['schoolName']
        self.session = requests.session()
        headers = {
            'User-Agent': 'Mozilla/5.0 (Linux; U; Android 8.1.0; zh-cn; BLA-AL00 Build/HUAWEIBLA-AL00) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/57.0.2987.132 MQQBrowser/8.9 Mobile Safari/537.36',
        }
        self.session.headers = headers
        self.login_url = 'https://ccut.campusphere.net/iap/login?service=https%3A%2F%2Fccut.campusphere.net%2Fportal%2Flogin'
        self.host = 'https://ccut.campusphere.net/'
        self.login_host = 'https://ccut.campusphere.net/'
        self.loginEntity = None

    def login(self):
        self.loginEntity = iapLogin(self.username, self.password, self.login_url, self.login_host, self.session)
        self.session.cookies = self.loginEntity.login()


class AutoSign:
    # 初始化签到类
    def __init__(self, todayLoginService: TodayLoginService, userInfo):
        self.session = todayLoginService.session
        self.host = todayLoginService.host
        self.userInfo = userInfo
        self.taskInfo = None
        self.task = None
        self.form = {}
        self.fileName = None

    # 获取未签到的任务
    def getUnSignTask(self):
        headers = self.session.headers
        headers['Content-Type'] = 'application/json'
        # 第一次请求接口获取cookies（MOD_AUTH_CAS）
        url = f'{self.host}wec-counselor-sign-apps/stu/sign/getStuSignInfosInOneDay'
        self.session.post(url, headers=headers, data=json.dumps({}), verify=False)
        # 第二次请求接口，真正的拿到具体任务
        res = self.session.post(url, headers=headers, data=json.dumps({}), verify=False).json()
        if len(res['datas']['unSignedTasks']) < 1:
            raise Exception('当前暂时没有未签到的任务哦！')
        # 获取最后的一个任务
        latestTask = res['datas']['unSignedTasks'][0]
        self.taskInfo = {
            'signInstanceWid': latestTask['signInstanceWid'],
            'signWid': latestTask['signWid']
        }

    # 获取具体的签到任务详情
    def getDetailTask(self):
        url = f'{self.host}wec-counselor-sign-apps/stu/sign/detailSignInstance'
        headers = self.session.headers
        headers['Content-Type'] = 'application/json'
        res = self.session.post(url, headers=headers, data=json.dumps(self.taskInfo), verify=False).json()
        self.task = res['datas']

    # 上传图片到阿里云oss
    def uploadPicture(self):
        url = f'{self.host}wec-counselor-sign-apps/stu/oss/getUploadPolicy'
        res = self.session.post(url=url, headers={'content-type': 'application/json'}, data=json.dumps({'fileType': 1}),
                                verify=False)
        datas = res.json().get('datas')
        fileName = datas.get('fileName')
        policy = datas.get('policy')
        accessKeyId = datas.get('accessid')
        signature = datas.get('signature')
        policyHost = datas.get('host')
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:50.0) Gecko/20100101 Firefox/50.0'
        }
        multipart_encoder = MultipartEncoder(
            fields={  # 这里根据需要进行参数格式设置
                'key': fileName, 'policy': policy, 'OSSAccessKeyId': accessKeyId, 'success_action_status': '200',
                'signature': signature,
                'file': ('blob', open(self.userInfo['photo'], 'rb'), 'image/jpg')
            })
        headers['Content-Type'] = multipart_encoder.content_type
        self.session.post(url=policyHost,
                          headers=headers,
                          data=multipart_encoder)
        self.fileName = fileName

    # 获取图片上传位置
    def getPictureUrl(self):
        url = f'{self.host}wec-counselor-sign-apps/stu/sign/previewAttachment'
        params = {'ossKey': self.fileName}
        res = self.session.post(url=url, headers={'content-type': 'application/json'}, data=json.dumps(params),
                                verify=False)
        photoUrl = res.json().get('datas')
        return photoUrl

    # 填充表单
    def fillForm(self):
        # 判断签到是否需要照片
        if self.task['isPhoto'] == 1:
            self.uploadPicture()
            self.form['signPhotoUrl'] = self.getPictureUrl()
        else:
            self.form['signPhotoUrl'] = ''
        self.form['isNeedExtra'] = self.task['isNeedExtra']
        if self.task['isNeedExtra'] == 1:
            extraFields = self.task['extraField']
            userItems = self.userInfo['forms']
            extraFieldItemValues = []
            for i in range(len(extraFields)):
                if i >= len(userItems):
                    raise Exception("您的config表单中form字段不够，请检查")
                userItem = userItems[i]['form']
                extraField = extraFields[i]
                if self.userInfo['checkTitle'] == 1:
                    if userItem['title'].strip() != extraField['title'].strip():
                        raise Exception(
                            f'\r\n第{i + 1}个配置出错了\r\n您的标题为：{userItem["title"]}\r\n系统的标题为：{extraField["title"]}')
                extraFieldItems = extraField['extraFieldItems']
                flag = False
                data = []
                # 遍历所有的选项
                for extraFieldItem in extraFieldItems:
                    # 如果当前选项为历史选项，将临时保存一下以便config未找到对应值时输出
                    if extraFieldItem['isSelected']:
                        data.append(extraFieldItem['content'])
                    # 初始化局部变量 并初始化数据字典的key
                    extraFieldItemValue = {}
                    extraFieldItemValue.setdefault('extraFieldItemValue', None)
                    extraFieldItemValue.setdefault('extraFieldItemWid', None)
                    # 如果表单的选项值和配置的值相等
                    if extraFieldItem['content'] == userItem['value']:
                        extraFieldItemValue['extraFieldItemWid'] = extraFieldItem['wid']
                        # 如果是其它字段（other字段）
                        if extraFieldItem['isOtherItems'] == 1:
                            if 'other' in userItem:
                                flag = True
                                extraFieldItemValue['extraFieldItemValue'] = userItem['other']
                            else:
                                raise Exception(
                                    f'\r\n第{i + 1}个配置项的选项不正确，该字段存在“other”字段，请在配置文件“title，value”下添加一行“other”字段并且填上对应的值'
                                )
                        # 如果不是其它字段
                        else:
                            flag = True
                            extraFieldItemValue['extraFieldItemValue'] = userItem['value']
                        extraFieldItemValues.append(extraFieldItemValue)
                if not flag:
                    raise Exception(
                        f'\r\n第{i + 1}个配置出错了\r\n表单未找到你设置的值：{userItem["value"]}\r\n，你上次系统选的值为：{",".join(data)}')
            self.form['extraFieldItems'] = extraFieldItemValues
        self.form['signInstanceWid'] = self.task['signInstanceWid']
        self.form['longitude'] = self.userInfo['lon']
        self.form['latitude'] = self.userInfo['lat']
        self.form['isMalposition'] = self.task['isMalposition']
        # self.form['abnormalReason'] = self.userInfo['abnormalReason']
        self.form['position'] = self.userInfo['address']
        self.form['uaIsCpadaily'] = True
        self.form['signVersion'] = '1.0.0'

    # DES加密
    def DESEncrypt(self, s, key='b3L26XNL'):
        key = key
        iv = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        k = des(key, CBC, iv, pad=None, padmode=PAD_PKCS5)
        encrypt_str = k.encrypt(s)
        return base64.b64encode(encrypt_str).decode()

    # 提交签到信息
    def submitForm(self):
        extension = {
            "lon": self.userInfo['lon'],
            "model": "OPPO R11 Plus",
            "appVersion": "8.1.14",
            "systemVersion": "4.4.4",
            "userId": self.userInfo['username'],
            "systemName": "android",
            "lat": self.userInfo['lat'],
            "deviceId": str(uuid.uuid1())
        }
        headers = {
            'User-Agent': self.session.headers['User-Agent'],
            'CpdailyStandAlone': '0',
            'extension': '1',
            'Cpdaily-Extension': self.DESEncrypt(json.dumps(extension)),
            'Content-Type': 'application/json; charset=utf-8',
            'Accept-Encoding': 'gzip',
            'Host': re.findall('//(.*?)/', self.host)[0],
            'Connection': 'Keep-Alive'
        }
        res = self.session.post(f'{self.host}wec-counselor-sign-apps/stu/sign/submitSign', headers=headers,
                                data=json.dumps(self.form), verify=False).json()
        return res['message']


def getYmlConfig(yaml_file='config.yml'):
    file = open(yaml_file, 'r', encoding="utf-8")
    file_data = file.read()
    file.close()
    config = yaml.load(file_data, Loader=yaml.FullLoader)
    return dict(config)


def main():
    config = getYmlConfig()
    for index, user in enumerate(config['users']):
        print(f'{Utils.getAsiaTime()} 第{index + 1}个用户正在执行...')
        print(working(user))


def working(user):
    print(f'{Utils.getAsiaTime()} 正在获取登录地址')
    today = TodayLoginService(user['user'])
    print(f'{Utils.getAsiaTime()} 正在登录ing')
    today.login()
    print(f'{Utils.getAsiaTime()} 正在进行“签到”...')
    sign = AutoSign(today, user['user'])
    sign.getUnSignTask()
    sign.getDetailTask()
    sign.fillForm()
    msg = sign.submitForm()
    return msg


if __name__ == '__main__':
    main()
