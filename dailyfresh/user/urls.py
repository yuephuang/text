from django.urls import path, re_path
from django.contrib.auth.decorators import login_required
from . import views

urlpatterns = [
    # re_path(r'^register/$', views.register, name='register'),
    # path('register_handle/', views.register_handle,name='register_handle'),  # 注册处理
    re_path(r'^register/$', views.RegisterView.as_view(), name='register'),
    re_path(r'^active/(?P<token>[\s\S]*)/', views.ActiveView.as_view(), name='active'),  # 用户激活
    re_path(r'^login/$', views.LoginView.as_view(), name='login'),  # 登录
    re_path(r'^text/(?P<token>[\s\S]*)/', views.text1.as_view()),  # 用户激活
    # re_path(r'^info/$', login_required(views.UserInfoView.as_view()),name='info'),
    # re_path(r'^order/$', login_required(views.UserOrderView.as_view()), name='order'),
    # re_path(r'^site/$', login_required(views.UserSiteView.as_view()), name='site'),
    re_path(r'^info/$', views.UserInfoView.as_view(), name='info'),
    re_path(r'^order/$', views.UserOrderView.as_view(), name='order'),
    re_path(r'^site/$', views.UserSiteView.as_view(), name='site'),
    re_path(r'^logout/$',views.LogoutView.as_view(),name='logout'),
]
