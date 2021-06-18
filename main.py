# -*- coding: utf-8 -*-
import ast
import base64
import datetime
import json
import os
import re
import sys
import time
import uuid
from concurrent.futures import ProcessPoolExecutor
from urllib import parse

import requests
import requests.utils
import rsa
import urllib3
from loguru import logger

urllib3.disable_warnings()


class SuperFive(object):
    def __init__(self):
        print("""
        ███████╗██╗   ██╗██████╗ ███████╗██████╗     ███████╗██╗██╗   ██╗███████╗
        ██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗    ██╔════╝██║██║   ██║██╔════╝
        ███████╗██║   ██║██████╔╝█████╗  ██████╔╝    █████╗  ██║██║   ██║█████╗  
        ╚════██║██║   ██║██╔═══╝ ██╔══╝  ██╔══██╗    ██╔══╝  ██║╚██╗ ██╔╝██╔══╝  
        ███████║╚██████╔╝██║     ███████╗██║  ██║    ██║     ██║ ╚████╔╝ ███████╗
        ╚══════╝ ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝    ╚═╝     ╚═╝  ╚═══╝  ╚══════╝
        """)
        if not os.path.exists(".cookies"):
            self.get_cookies()
        with open(".cookies", "r") as f:
            self.cookies = f.read()
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Linux;Android 10;GM1910) AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/83.0.4103.106 Mobile Safari/537.36; unicom{version:android@8.0002}",
            "ContentType": "application/x-www-form-urlencoded;charset=UTF-8",
            "Cookie": self.cookies,
        }
        self.diff_time = self.local_unicom_time_diff()
        self.ac_id = self.get_ac_id()
        self.retry_count = 10

    @staticmethod
    def public_key():
        publicpem = (
            "-----BEGIN PUBLIC KEY-----\n"
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDc+CZK9bBA9IU+gZUOc6"
            "FUGu7yO9WpTNB0PzmgFBh96Mg1WrovD1oqZ+eIF4LjvxKXGOdI79JRdve9NPhQ"
            "o07+uqGQgE4imwNnRx7PFtCRryiIEcUoavuNtuRVoBAm6qdB0SrctgaqGfLgKvZHO"
            "nwTjyNqjBUxzMeQlEC2czEMSwIDAQAB\n"
            "-----END PUBLIC KEY-----"
        )
        publickey = rsa.PublicKey.load_pkcs1_openssl_pem(publicpem)
        return publickey

    def rsa_enc(self, a):
        enca = rsa.encrypt(a.encode("utf-8"), self.public_key())
        b64enca = base64.b64encode(enca).decode()
        quob64enca = parse.quote(b64enca, safe="")
        return quob64enca

    def mobile(self):
        phone = input("请输入你的手机号: ")
        if len(phone) != 11:
            logger.info("请输入11位手机号码,1秒后重新输入")
            time.sleep(1)
            return self.mobile()
        else:
            return phone

    def srcode(self):
        phone = self.mobile()
        headers = {"Content-Type": "application/x-www-form-urlencoded; Charset=UTF-8", "User-Agent": "okhttp/3.9.1"}
        quob64enc_phone = self.rsa_enc(phone)
        scparams = "mobile=%s&version=android%%408.0002&keyVersion=" % quob64enc_phone
        try:
            srcode = requests.post(
                url="https://m.client.10010.com/mobileService/sendRadomNum.htm",
                headers=headers,
                data=scparams,
                timeout=5,
            )
            srcodes = ast.literal_eval(srcode.content.decode("utf-8"))["rsp_desc"]
            if re.findall(r"验证码已发送", srcodes):
                logger.info("\n返回信息: " + srcodes)
                return phone, headers
            else:
                logger.error("\n返回信息: %s\n验证码发送失败哦" % srcodes)
                return self.srcode()
        except Exception as e:
            logger.error(f"\n可能程序出错了,正在重新运行程序，错误信息: {e}")
            self.get_cookies()

    def login(self, phone, headers):
        rcode = input("\n请输入验证码:")
        quob64enc_mob = self.rsa_enc(phone)
        quob64enc_rpw = self.rsa_enc(rcode)
        times = time.strftime("%Y%m%d%H%M%S", time.localtime(int(time.time())))
        uuidstr = str(uuid.uuid4()).replace("-", "")
        lgparams = (
            "yw_code=&loginStyle=0&deviceOS=android10&mobile=%s&"
            "netWay=4G&deviceCode=%s&"
            "isRemberPwd=true&version=android%%408.0002&"
            "deviceId=%s&password=%s&"
            "keyVersion=&pip=127.0.0.1&provinceChanel=general&voice_code=&"
            "appId=ChinaunicomMobileBusiness&voiceoff_flag=1&deviceModel=GM1910&"
            "deviceBrand=OnePlus&timestamp=%s" % (quob64enc_mob, uuidstr, uuidstr, quob64enc_rpw, times)
        )
        try:
            login = requests.post(
                "https://m.client.10010.com/mobileService/radomLogin.htm",
                headers=headers,
                data=lgparams,
                timeout=5,
            )
            logins = ast.literal_eval(login.content.decode("utf-8"))
            if re.findall(r"proName", str(logins), flags=re.I):
                logger.info(
                    "\n返回登录成功信息:\n%s省 %s市 %s\n"
                    % (logins["list"][0]["proName"], logins["list"][0]["cityName"], logins["list"][0]["num"])
                )
                return login
            elif re.findall(r"验证码错误", str(logins)):
                logger.error("\n返回信息: %s\n输入验证码错误,1秒后重新输入,如果多次输入正确却提示错误的请重新打开程序获取新的验证码" % (logins["dsc"]))
                time.sleep(1)
                return self.login(phone, headers)
        except Exception as e:
            logger.error(f"\n可能程序出错了,正在重新运行程序，错误信息: {e}")
            self.get_cookies()

    def get_cookies(self):
        phone, headers = self.srcode()
        login = self.login(phone, headers)
        dict_cookies = requests.utils.dict_from_cookiejar(login.cookies)
        self.cookies = "; ".join(
            [
                f"{key}={value}"
                for key, value in dict_cookies.items()
                if key not in ["cw_mutual", "u_account", "c_mobile"]
            ]
        )
        with open(".cookies", "w") as f:
            f.write(self.cookies)
        return self.cookies

    @staticmethod
    def unicom_time():
        url = "https://m.client.10010.com/welfare-mall-front-activity/mobile/activity/getCurrentTimeMillis/v2"
        ret = requests.get(url=url, verify=False).json()
        return int(ret["resdata"]["currentTime"])

    @staticmethod
    def local_time():
        step_error_time_ms = 500
        return int(round(time.time() * 1000)) - int(step_error_time_ms)

    def local_unicom_time_diff(self):
        return self.local_time() - self.unicom_time()

    def get_ac_id(self):
        ac_idpt = requests.post(
            url="https://m.client.10010.com/h5-web_pro/interface/service_0005_0002",
            headers=self.headers,
            data=json.dumps({"id": "88888", "_su_pass": "_sunc_vl"}),
            timeout=5,
            verify=False,
        ).text
        ac_id = re.match(r'.*\\"activityNumber\\":\\"(.*?\d+)\\".*', ac_idpt, flags=re.I).group(1)
        return ac_id

    def get_goods(self):
        try:
            good_response = requests.get(
                url=f"https://m.client.10010.com/welfare-mall-front-activity/super/five/get619Activity/v1",
                headers=self.headers,
                verify=False,
                timeout=5,
                params={"acId": self.ac_id},
            ).json()
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, ValueError) as e:
            logger.error(e)
            return self.get_goods()
        if re.findall(r"获取用户信息异常", str(good_response)):
            logger.error("返回信息: " + good_response["msg"] + "\n联通登录状态失效了,请重新获取Cookie")
            self.cookies = self.get_cookies()
            self.headers["Cookie"] = self.cookies
            return self.get_goods()
        tab_list = good_response["resdata"]["tabList"]
        good_list = []
        state_map = {"00": "未开始", "10": "抢购", "20": "查看", "30": "无法抢购", "40": "抢光", "50": "待支付", "60": "处理中"}
        start_index = 0
        for tab in tab_list:
            for goods in tab["goodsList"]:
                start_index += 1
                good_list.append(
                    {
                        "index": str(start_index).rjust(2),
                        "timeNav": tab["timeNav"],
                        "start_time": int(
                            time.mktime(
                                time.strptime(
                                    time.strftime("%Y-%m-%d", time.localtime(int(time.time())))
                                    + " "
                                    + tab["timeNav"]
                                    + ":00",
                                    "%Y-%m-%d %H:%M:%S",
                                )
                            )
                            * 1000
                        ),
                        "state": state_map.get(goods["state"], "未知状态").ljust(4),
                        "goodsName": goods["goodsName"],
                        "goodsId": goods["goodsId"],
                        "price": str(goods["price"]) + "0"
                        if re.findall(r"\.", str(goods["price"]))
                        else str(goods["price"]) + ".00",
                    }
                )
        good_list_str = "\n".join(
            [
                " ".join([str(one) for key, one in good.items() if key not in ["start_time", "goodsId"]])
                for good in good_list
            ]
        )
        print(good_response["msg"] + "\n\n" + good_list_str + "\n")
        select_good = input("请输入对应的数字选择商品(多选要用 . 分割,如 1.2.3): ")
        select_good_list = []
        select_good = select_good if select_good.endswith(".") else select_good + "."
        for num in re.findall(r"\d+", select_good):
            select_good_list.append(good_list[int(num) - 1])
        return select_good_list

    def start(self, start_time, count):
        if count == 1:
            logger.info("正在等待到达设定时间:{}，检测本地时间与京东服务器时间误差为【{}】毫秒".format(start_time, self.diff_time))
        while True:
            if self.local_time() - self.diff_time >= start_time:
                break
            else:
                time.sleep(0.001)

    def captcha(self, app_id):
        try:
            imagep = requests.get(
                url=f"https://act.10010.com/riskService?appId={app_id}&method=send&riskCode=image",
                headers=self.headers,
                verify=False,
                timeout=10,
            ).content.decode("utf-8")
            logger.info(imagep)
            imagepj = ast.literal_eval(imagep)
            image_url = imagepj.get("imageUrl")
            if image_url is None:
                logger.error("无法获取验证码了")
            else:
                image_url = image_url.replace("\\", "")
                image = requests.get(image_url, headers=self.headers, verify=False, timeout=5)
                with open("unifricaptcha.jpg", "wb") as jpg:
                    jpg.write(image.content)
                    logger.info("验证码 unifricaptcha.jpg 已下载到该目录下,如果没有自动打开图片,请手动打开图片查看")
                if sys.platform == "win32":
                    os.system('start "" "unifricaptcha.jpg"')
                elif sys.platform == "darwin":
                    os.system('open "unifricaptcha.jpg"')
                else:
                    os.system('xdg-open "unifricaptcha.jpg"')
                captcha = input("输入验证码(不区分大小写)后按确定:")
                riskr = requests.get(
                    url="https://act.10010.com/riskService",
                    headers=self.headers,
                    verify=False,
                    timeout=5,
                    params={
                        "appId": app_id,
                        "method": "check",
                        "riskCode": "image",
                        "checkCode": captcha,
                        "systemCode": "19991",
                    },
                ).content.decode("utf-8")
                riskrj = ast.literal_eval(riskr)
                if riskrj.get("token") is not None:
                    logger.info("号码已正常,可以继续抢购了")
                else:
                    logger.error("验证码出错,重新获取后再输入")
                    self.captcha(app_id)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            logger.error("该网址有概率访问不了,5秒后重新尝试验证...")
            time.sleep(5)
            self.captcha(app_id)
        except Exception as err:
            logger.error(err)
            self.captcha(app_id)

    def get_order(self, order_params, start_time, count):
        while count <= self.retry_count:
            self.start(start_time, count)
            logger.info(f"时间到达，开始执行第{count}次……")
            count += 1
            while True:
                try:
                    order_response = requests.get(
                        url="https://m.client.10010.com/welfare-mall-front/mobile/api/bj2402/v1",
                        headers=self.headers,
                        params=order_params,
                        verify=False,
                        timeout=2,
                    ).json()
                    if "下单成功" in str(order_response):
                        logger.success(f"下单成功")
                        return order_response
                    elif any(name in str(order_response) for name in ["达到上限", "数量限制", "次数限制", "最大限制", "商品已抢光"]):
                        logger.warning(f"已有订单或不能再次购买该商品")
                        break
                    elif "无法购买请稍候再试" in str(order_response):
                        logger.warning(f"可能已被限制当天所有活动,请下次再参加")
                        return self.get_order(order_params, start_time, count)
                    elif any(name in str(order_response) for name in ["活动太火爆", "系统开小差了", "下单太频繁了"]):
                        resdata = order_response["resdata"]
                        if not resdata:
                            logger.warning(order_response.get("msg"))
                            return self.get_order(order_params, start_time, count)
                        else:
                            logger.error("处于半黑状态,需要过一下验证才能继续抢购哦")
                            return self.captcha(app_id=resdata)
                    else:
                        return self.get_order(order_params, start_time, count)
                except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, ValueError):
                    logger.error(("可能网络出错了, %s 正在重新尝试下单" % (datetime.datetime.now().strftime("%M:%S"))).ljust(50))
                    return self.get_order(order_params, start_time, count)
                except Exception as err:
                    logger.error(err)
                    return self.get_order(order_params, start_time, count)

    def main(self):
        select_good_list = self.get_goods()
        good_list_str = "\n".join(
            [
                " ".join([str(one) for key, one in good.items() if key not in ["start_time", "goodsId"]])
                for good in select_good_list
            ]
        )
        print(good_list_str)
        with ProcessPoolExecutor(len(select_good_list)) as pool:
            for select_good in select_good_list:
                start_time = select_good.get("start_time")
                order_params = (
                    'reqsn=&reqtime=&cliver=&reqdata={"goodsId":"%s","payWay":"01",'
                    '"amount":"%s","saleTypes":"C","points":"0","beginTime":"%s",'
                    '"imei":"undefined","sourceChannel":"","proFlag":"","scene":"","pormoterCode":"",'
                    '"sign":"","oneid":"","twoid":"","threeid":"","maxcash":"","floortype":"undefined",'
                    '"FLSC_PREFECTURE":"SUPER_FRIDAY","launchId":"","platAcId":"%s"}'
                    % (select_good.get("goodsId"), select_good.get("price"), start_time, self.ac_id)
                )
                pool.submit(self.get_order, order_params, start_time, 1)


if __name__ == "__main__":
    SuperFive().main()
