---
title: 友情链接  # 在导航栏中显示的名称
icon: fas fa-link  # 在导航栏中显示的图标
order: 5           # 在导航栏中的排列顺序，数字越小越靠前
---

<ul>
{% for friend in site.data.friends %}
  <li>
    <a href="{{ friend.href }}" target="_blank">{{ friend.title }}</a>
  </li>
{% endfor %}
</ul>
