from django.conf.urls import url
from views import index, login, register, success, logout, delete
urlpatterns = [
    url(r'^$', index, name='index'),
    url(r'^login$', login, name='login'),
    url(r'^register$', register, name='register'),
    url(r'^success$', success, name='success'),
    url(r'^logout$', logout, name='logout'),
    url(r'^delete/(?P<user_id>\d+)$', delete, name='delete')
]
