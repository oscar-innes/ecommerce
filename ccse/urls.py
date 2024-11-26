from django.urls import path 
from . import views 
  
urlpatterns = [ 
    path("", views.home, name="home"), 
    path("contact/", views.contact, name="contact"),  
    path("products/", views.products, name="products"), 
    path("admin/", views.admin, name="admin"),
    path("registration/", views.registration, name="registration"),
    path("postregis/", views.postregis, name="postregis"),
    path("user_login/", views.cust_login, name="login"),
    path("postlogin/", views.postlogin, name="postlogin"),
    path("add_to_cart/", views.add_to_cart, name="add_to_cart"),
    path("add_stock/", views.add_stock, name="add_stock"),
    path("add_product/", views.add_product, name="add_product"),
    path("removeproduct/<str:product_name>/", views.remove1item, name="remove1product"),
    path("addproduct/<str:product_name>/", views.add1item, name="add1product"),
    path("logout/", views.logout, name="logout"),
    path("basket/", views.basket, name="basket"),
    path("clearbasket/", views.clearbasket, name="clearbasket"),
    path("paynow/", views.paynow, name="paynow"),
    path("payment/", views.payment, name="payment"),
    path("forgotpass/", views.forgot_pass, name="forgotpass"),
    path("verify_change/", views.verify_change, name="verify_change"),
    path("delete_file/", views.delete_file, name="delete_file"),
    path("account/", views.account, name="account"),
    path("cancelorder/", views.cancelorder, name="cancelorder"),
    path("changepass/", views.change_pass, name="changepass"),
    path("change_role/", views.change_role, name="change_role"),
    path("order_status/", views.order_status, name="order_status_change"),
    path("verify2fa/<str:username>/", views.verify2fa, name="verify2fa"),
    

]
