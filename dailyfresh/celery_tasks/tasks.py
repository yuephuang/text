from celery import Celery
from django.conf import settings
from django.core.mail import send_mail
import time
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dailyfresh.settings')
django.setup()

# 创建一个Celery类的实例对象
app = Celery('celery_tasks.tasks', broker='redis://127.0.0.1:6379/8')




# 定义任务函数
@app.task
def send_register_active_email(to_email, username, token):
    """发送激活邮件"""

    subject = '你好，我的宝贝'
    message = '<h1>{0},欢迎</h1><br/><a>http://127.0.0.1:8000/user/active/{1}</a>'.format(username, token)
    send_mail(subject, message=None, from_email=settings.EMAIL_FROM,
              recipient_list=[to_email], html_message=message)
    time.sleep(5)
