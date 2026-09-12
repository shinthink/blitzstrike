from django.http import JsonResponse
from django.db import connection
from django.shortcuts import render


def search(request):
    # VULNERABLE: raw SQL interpolation of user input
    q = request.GET.get('q')
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE name LIKE '%%%s%%'" % q)
    rows = cursor.fetchall()
    return JsonResponse({'rows': rows})


def export(request):
    # VULNERABLE: command execution from user input
    import os
    file = request.GET.get('file')
    os.system("tar -czf /tmp/export.tar.gz " + file)
    return JsonResponse({'ok': True})


def show(request):
    # SAFE: Django ORM (parameterized)
    from .models import User
    uid = request.GET.get('id')
    user = User.objects.filter(id=uid).first()
    return JsonResponse({'user': str(user)})


def preview(request):
    # SAFE: escaped output
    from django.utils.html import escape
    html = request.GET.get('html')
    return JsonResponse({'content': escape(html)})
