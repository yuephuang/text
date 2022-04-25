from django.shortcuts import render, redirect
import re
from django.http import HttpResponse
from django.urls import reverse
from user.models import User, Address
from django.views.generic import View
from dailyfresh.settings import SECRET_KEY, HOSTS
from authlib.jose import jwt
from celery_tasks.tasks import send_register_active_email
from django.contrib.auth import login, logout
from django.contrib.auth.hashers import check_password
from utils.mixin import LoginRequireMixin
from django_redis import get_redis_connection
from goods.models import GoodsSKU

# Create your views here.
def register(request):
    """返回注册页面"""
    return render(request, 'df_user/register.html')


def register_handle(request):
    """进行注册处理"""

    # 接受数据
    username = request.POST.get('user_name')
    password = request.POST.get('pwd')
    r_password = request.POST.get('cpwd')
    email = request.POST.get('email')
    allow = request.POST.get('allow')

    # 进行数据校验
    if not all([username, password, r_password, email]):
        # 数据不完整
        return render(request, 'df_user/register.html', {'errmsg': '数据不完整'})

    # 校验邮箱
    if not re.match(r'^[a-z\d][\w.\-]*@[a-z\d\-]+(\.[a-z]{2,5}){1,2}$', email):
        return render(request, 'df_user/register.html', {'errmsg': '邮箱格式错误'})
    # 校验密码
    if password != r_password:
        return render(request, 'df_user/register.html', {'errmsg': '密码错误'})
    # 校验协议
    if allow != 'on':
        return render(request, 'df_user/register.html', {'errmsg': '请同意协议'})

    # 进行业务处理：进行用户注册
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        user = None

    if user:
        return render(request, 'df_user/register.html', {'errmsg': '用户名已存在'})

    user = User.objects.create_user(username=username, email=email, password=password)
    user.is_active = 0
    user.save()
    # 返回应答,跳转首页
    return redirect('goods:index')


class RegisterView(View):
    """注册"""

    def get(self, request):
        """显示注册页面"""
        return render(request, 'df_user/register.html')

    def post(self, request):
        '''进行注册页面'''

        # 接受数据
        username = request.POST.get('user_name')
        password = request.POST.get('pwd')
        r_password = request.POST.get('cpwd')
        email = request.POST.get('email')
        allow = request.POST.get('allow')

        # 进行数据校验
        if not all([username, password, r_password, email]):
            # 数据不完整
            return render(request, 'df_user/register.html', {'errmsg': '数据不完整'})

        # 校验邮箱
        if not re.match(r'^[a-z\d][\w.\-]*@[a-z\d\-]+(\.[a-z]{2,5}){1,2}$', email):
            return render(request, 'df_user/register.html', {'errmsg': '邮箱格式错误'})
        # 校验密码
        if password != r_password:
            return render(request, 'df_user/register.html', {'errmsg': '密码错误'})
        # 校验协议
        if allow != 'on':
            return render(request, 'df_user/register.html', {'errmsg': '请同意协议'})

        # 进行业务处理：进行用户注册
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            user = None

        if user:
            return render(request, 'df_user/register.html', {'errmsg': '用户名已存在'})

        user = User.objects.create_user(username=username, email=email, password=password)
        user.is_active = 0
        user.save()

        # 发送激活邮箱，包含激活链接：
        # 生成激活token
        header = {'alg': 'HS256'}
        info = {'confirm': user.id}
        info.update()
        token = jwt.encode(header=header, payload=info, key=SECRET_KEY)
        token = token.decode('utf8')
        # subject = '你好，我的宝贝'
        # message = '<h1>{0},欢迎</h1><br/><a>http://127.0.0.1:8000/user/active/{1}</a>'.format(username, token)
        # send_mail(subject, message=None, from_email=settings.EMAIL_FROM,
        #           recipient_list=[email], html_message=message)
        send_register_active_email.delay(email, username, token)
        # 返回应答,跳转首页
        return redirect('goods:index')


class ActiveView(View):
    def get(self, request, token):
        """进行用户激活"""
        # 进行解密，获取用户信息

        try:
            info = jwt.decode(token, SECRET_KEY)
            user_id = info['confirm']
            # 根据id获取用户信息
            user = User.objects.get(id=user_id)
            user.is_active = 1
            user.save()
            # 跳转到登录页面
            return redirect('user:login')
        except Exception as e:
            return HttpResponse('激活已过期')


class LoginView(View):
    """登录"""

    def get(self, request):
        # 判断是否记住了用户名
        if 'username' in request.COOKIES:
            username = request.COOKIES.get('username')
            checked = 'checked'
        else:
            username = ''
            checked = ''
        return render(request, 'df_user/login.html',
                      {'username': username, 'checked': checked})

    def post(self, request):
        """登录校验"""
        username = request.POST.get('username')
        password = request.POST.get('pwd')
        if not all([username, password]):
            return render(request, 'df_user/login.html', {'errmsg': '数据不完整'})

        # user = authenticate(username=username, password=password)
        try:
            user = User.objects.get(username=username)
            result = check_password(password, user.password)
            response = redirect('goods:index')
            # 记住用户名
            remember = request.POST.get('remember')
            if remember == 'on':
                response.set_cookie('username', username, max_age=3600 * 7 * 24)
            else:
                response.delete_cookie('username')

            if not result:
                return render(request, 'df_user/login.html', {'errmsg': '用户名或密码错误'})

        except:
            return render(request, 'df_user/login.html', {'errmsg': '用户名或密码错误'})

        if user.is_active:
            login(request, user)
            next_url = request.GET.get('next', reverse('goods:index'))
            return redirect(next_url)
        else:
            return render(request, 'df_user/login.html', {'errmsg': '账户未激活'})


class LogoutView(View):
    '''推出登录'''

    def get(self, request):
        logout(request)
        return redirect('user:login')


class UserInfoView(LoginRequireMixin, View):
    '''用户信息显示'''

    def get(self, request):
        # 获取用户个人信息
        user = request.user
        address = Address.objects.get_default_address(user)
        # 获取用户的历史浏览记录
        # from redis import StrictRedis
        # StrictRedis(host=HOSTS, port=6379, db=9)
        con = get_redis_connection('default')
        history_key = 'history_%d' % user.id
        # 获取用户最新浏览的五条数据
        sku_ids = con.lrange(history_key, 0, 4)
        # 从数据库中查询用户的具体模型
        # goods_li = GoodsSKU.objects.filter(id__in=sku_ids)
        # goods_res = []
        # for a_id in sku_ids:
        #     for goods in goods_li:
        #         if a_id == goods.id:
        #             goods_res.append(goods)
        goods_li = []
        for id in sku_ids:
            goods = GoodsSKU.objects.get(id=id)
            goods_li.append(goods)

        # 组织上下文
        context = {'page': 'user',
                   'address': address,
                   'goods_li': goods_li}

        return render(request, 'df_user/user_center_info.html', context)


class UserOrderView(LoginRequireMixin, View):
    '''用户信息显示'''

    def get(self, request):
        # 获取用户的订单信息

        return render(request, 'df_user/user_center_order.html', {'page': 'order'})


class UserSiteView(LoginRequireMixin, View):
    '''收获地址显示'''

    # 获取用户的收货地址

    def get(self, request):
        user = request.user
        # try:
        #     address = Address.objects.get(user=user, is_default=True)
        # except Address.DoesNotExist:
        #     # 不存在默认收获地址
        #     address = None
        address = Address.objects.get_default_address(user)
        return render(request, 'df_user/user_center_site.html', {'page': 'site', 'address': address})

    def post(self, request):
        # 接收数据
        reveiver = request.POST.get("receive")
        addr = request.POST.get("address")
        zip_code = request.POST.get("zip_code")
        phone = request.POST.get("phone")
        # 校验数据
        if not all([reveiver, addr, phone]):
            return render(request, 'df_user/user_center_site.html',
                          {'errmsg': '数据不完整'})

        # 校验手机号
        if not re.match(r'^1[3|4|5|7|8]\d{9}', phone):
            return render(request, 'df_user/user_center_site.html',
                          {'errmsg': '手机号不正确'})
        # 业务处理：地址添加
        # 如何用户已存在默认收货地址。添加的地址不作为默认收获地址，否则作为默认收获地址
        # 获取用户的user对象
        user = request.user
        # try:
        #     address = Address.objects.get(user=user, is_default=True)
        # except Address.DoesNotExist:
        #     # 不存在默认收获地址
        #     address = None
        address = Address.objects.get_default_address(user)

        if address:
            is_default = False
        else:
            is_default = True
        # 添加地址
        Address.objects.create(user=user,
                               receiver=reveiver,
                               addr=addr,
                               zip_code=zip_code,
                               phone=phone,
                               is_default=is_default)
        # Address.save()
        # 返回应答,刷新
        return redirect('user:site')


class text1(View):
    def get(self, request, token):
        return HttpResponse(token)
