# การทำ Thread Timeout ให้กับ Function ใน Python 

สำหรับการพัฒนาโปรแกรมส่วนใหญ่มักมีความเกี่ยวข้องกับค่าเวลาอย่างหลีกเลี่ยงไม่ได้ ยกตัวอย่างเช่น การส่ง OTP(One Time Password) ไปให้กับผู้ใช้งานระบบ เพื่อกรอกใน Multi Factor Authentication ก็จะมีเวลาสำหรับนับถอยหลัง โดยหากเวลานับถอยหลังจนถึง 0 ก็จะยกเลิกกระบวณการทำงานทั้งหมด หรือทำการสุ่ม Ref. ID ใหม่ให้กับผู้ใช้นั่นเอง 

สำหรับบทความนี้จะเป็นการบอกเล่าถึงวิธีการสร้าง Thread บนภาษา Python เพื่อจำกัดเวลาในการทำงานของ Thread แต่ละตัว โดยหากตัวใดตัวหนึ่งหมดเวลาก่อน ก็จะส่ง Signal ไปยัง Thread อื่นๆ เพื่อหยุดการทำงานลง เพื่อทำกระบวนการอื่นต่อไปตามที่ต้องการ 

``` python
from threading import Thread, Event
import time

# Event object used to send signals from one thread to another
stop_event = Event()


def icesuntisuk_github_io():
    print('Starting Icesuntisuk function')
    i = 0
    while True:
        i += 1
        print(i)
        time.sleep(1)
        # Here we make the check if the other thread sent a signal to stop execution.
        if stop_event.is_set():
            break


def func_return_zero():
    print('Starting function Return ZERO')
    if stop_event.is_set():
        return 0


if __name__ == '__main__':
    # Create Thread
    t1 = Thread(target=icesuntisuk_github_io, name='Icesuntisuk Function')
    t2 = Thread(target=func_return_zero, name='Return 0 Function')
    # start the thread and we wait 5 seconds before the code continues to execute.
    t1.start()
    t2.start()
    t1.join(timeout=5)
    t2.join(timeout=10)
    # send a signal that the other thread should stop.
    stop_event.set()
    print(f'{t1} timeouts!')
    print(f'{t2} is END')
```

**ผลการทดสอบ**

![](/KB/img/ThreadTimeout.png)

จากตัวอย่างด้านบนจะเห็นได้ว่า ผมได้ทำการสร้าง Function ไว้ 2 Function ได้แก่ icesuntisuk_github_io และ func_return_zero โดยแต่ละตัวจะมีการตั้งค่า Timeout ที่แตกต่างกัน โดย icesuntisuk_github_io ตั้งไว้ที่ 5 วินาที และ func_return_zero ตั้งไว้ที่ 10 วินาที ซึ่งจะเห็นได้ว่าแต่ละ Function จะมีการใส่ **if stop_event.is_set()** เพื่อหยุดการทำงานไว้ ซึ่งหาก thread 1 หรือ Function icesuntisuk_github_io  หมดเวลาก่อน ก็จะส่ง Signal **stop_event.set()** สำหรับหยุดทำงานของ Thread ที่เหลือ ทำให้ทุกๆ Functionn หยุดการทำงานนั่นเอง ซึ่งจะเห็นได้ว่า thread 2 มีการหน่วงเวลาไว้ที 10 วินาที แต่ก็จะถูกหยุดการทำงานโดยทันทีนั่นเอง 

**Powered By** : 
Icesuntisuk 
๖ ม.ค.๖๔