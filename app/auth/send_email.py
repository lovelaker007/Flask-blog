# -*- coding:utf-8 -*-

import smtplib
import threading
from email.header import Header
from email.mime.text import MIMEText
 

# 第三方 SMTP 服务
mail_host = "smtp.163.com"      # SMTP服务器
mail_user = "17718396856@163.com"                  # 用户名
mail_pass = "lovelaker24"               # 授权密码，非登录密码
 
def send_mail_t(subject, content, from_account, to_account):
    message = MIMEText(content, 'plain', 'utf-8')  # 内容, 格式, 编码
    message['From'] = "{}".format(from_account)
    message['To'] = ",".join(to_account)
    message['Subject'] = subject

    smtpObj = smtplib.SMTP_SSL(mail_host, 465)  # 启用SSL发信, 端口一般是465
    smtpObj.login(mail_user, mail_pass)  # 登录验证

    try:
        smtpObj.sendmail(from_account, to_account, message.as_string())  # 发送
    except smtplib.SMTPException as e:
        print(e)
    else:
        print('send email done') 
    finally:
        smtpObj.quit()

def send_mail(subject,  content, from_account, to_account):
    t = threading.Thread(target=send_mail_t, args=(subject, content, from_account, to_account))
    t.start()

 
if __name__ == '__main__':
    # sendEmail()
    # receiver = '***'
    # send_email2(mail_host, mail_user, mail_pass, receiver, title, content)

    subject = 'if you'
    content = 'if you really want it'
    from_account = '17718396856@163.com'
    to_account = ['823827481@qq.com']
    send_mail(subject, content, from_account, to_account)
