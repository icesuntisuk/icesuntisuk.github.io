# How to enable 2-Factor Authen on Github

สำหรับบทความนี้จะเป็นการแนะนำวิธีการเปิดใช้งาน 2-Factor Authen บน Github ซึ่งเป็นเว็บไซต์ยอดนิยมของเหล่าผู้พัฒนาระบบโดยทำหน้าที่สำหรับ Control version ของ Software ที่พัฒนาได้ ฉะนั้นการเข้าถึงข้อมูลบน Github ของผู้ใช้นั้นๆ ได้จะสามารถทำให้เข้าถึง Source Code ของผู้พัฒนาได้โดยตรง ทำให้การเปิดใช้งาน Multi-Factor Authen เป็นสิงสำคัญ 

Step1: Login ของ Github หน้าตาจะประมาณนี้ให้ดำเนินการ Login เข้าไปตามปกติ
![](/KB/img/GH-login.jpg)

Step2: เข้าไปที่หน้า Setting
![](/KB/img/GH-setting.jpg)

Step3: คลิ๊กที่เมนู Account security
![](/KB/img/GH-AS.jpg)

Step4: เลือก Enable two factor authentication
![](/KB/img/GH-Enable.jpg)

Step5: เลือกการ Authen ที่ต้องการโดยระบบสามารถทำ 2 Factor Authen ได้ผ่านทาง App ของ Github หรือใช้ SSH ในการ Authen ได้ ทั้งนี้เราจะใช้ App สำหรับการ Authen 
![](/KB/img/GH-apporssh.jpg)

Step6: จะมี Key สำหรับ Recovery ให้เราได้เก็บไว้ในเครื่อง 
![](/KB/img/GH-downloadkey.jpg)