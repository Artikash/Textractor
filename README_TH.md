# Textractor

![How it looks](screenshot.png)

[Español](README_ES.md) ● [简体中文](README_SC.md) ● [日本語](README_JP.md) ● [Русский](README_RU.md) ● [Bahasa](README_ID.md) ● [Português](README_PT.md) ● [ภาษาไทย](README_TH.md) ●

**Textractor** 
(หรือ NextHooker) คือโปรแกรมโอเพนซอร์ซสำหรับปฏิบัติการที่มีหน้าที่เพื่อเชื่อมกับตัวอักษรกับเกมจากที่มาจากระบบปฏิบัติการ Window/Wine โดยมีแบบดังเดิมมาจาก [ITHVNR](http://www.hongfire.com/forum/showthread.php/438331-ITHVNR-ITH-with-the-VNR-engine).<br>
สามารถดูตัวอย่างวิธีการใช้งาน [วีดีโอตัวอย่างการใช้งาน](https://tinyurl.com/textractor-tutorial) เพื่อที่จะแสดงความเข้าใจคร่าวๆเกี่ยวกับโปรแกรม.

[![Donate](https://www.paypalobjects.com/en_US/i/btn/btn_donate_SM.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=akashmozumdar%40gmail.com&item_name=Textractor%20development&currency_code=USD)

## ดาวน์โหลด

Textractor รุ่นล่าสุดสามารถดาวน์โหลดจาก [ที่นี้](https://github.com/Artikash/Textractor/releases).<br>
ITHVNR รุ่นสุดท้ายสามารถดาวน์โหลดได้ [ที่นี้](https://drive.google.com/open?id=13aHF4uIXWn-3YML_k2YCDWhtGgn5-tnO).<br>
ถ้าหากมีปัญหาขณะที่เปิด Textractor ลองเปิด vcredist

## คุณสมบัติ

- Highly extensible and customizable
- ต่อยอดได้ไกล และ ปรับแต่งได้ง่าย
- สามารถเชื่อม/ดึงคำแปลได้จากระบบเกมหลายเกม (รวมทั่งเกมที่ไม่ได้รองรับโดยโปรแกรม Visual Novel Reader)
- สามารถเชื่อมตัวอักษรโดยการใช้ /H "hook" (รหัสเชื่อม) และยังรองรับการใช้รหัสของ AGTH 
- สามารถการดึงข้อมูลโดยใช้รหัส /R "read 

## ความช่วยเหลือ

ในกรณีที่พบกับปัญหาระหว่างใช้งานโปรแกรม หรือ เกมที่ Textractor ไม่สามารถเชื่อมข้อมูล, หรือแนะนำต่างๆ สามารถแจ้งให้ทราบได้จากเว็บไซต์ที่ดาวน์โหลด Textractor. 
ถ้าหากมีเกมใดที่มีปัญหาการเชื่อมกรุณาส่งอีเมลสถานที่ที่สามารถดาวน์โหลดเกมได้ หรือ ส่งของขวัญเกมผ่านทาง [Steam](https://steamcommunity.com/profiles/76561198097566313/).

## ส่วนขยาย

กรุณาลองสำรวจ [ตัวอย่างของส่วนขยาย](https://github.com/Artikash/ExampleExtension) เพื่อที่จะเรียนรู้เกี่ยวกับการเขียนส่วนขยาย.<br>
และลองดูโฟลเดอร์ extensions สำหรับตัวอย่างการทำงานของส่วนขยาย

## การสนับสนุน

การสนับสนุนใดๆนั่นยินดีเป็นอย่างยิ่ง! สามารถส่งอีเมลมาได้ตลอดเวลาที่ akashmozumdar@gmail.com ถ้าหากมีคำถามเกี่ยวกับโค้ด.<br>

## โครงสร้างโปรแกรม

ฐานของโปรแกรม (โฟลเดอร์ GUI/host) ส่งข้อมูลจาก texthook.dll (ที่ถูกสร้างจาก texthook โฟลเดอร์) ไปยังเกมเป้าหมาย และ เชื่อมทั่งสองอย่างเข้าด้วยกัน<br>
ฐานโปรแกรมเขียนผ่านฝั่ง hostPipe(ท่อเชื่อมฝั่งฐานข้อมูล) ในขณะที่ตัวดึงตัวอักษรที่ทางฝั่ง hookPipe(ท่อเชื่อมฝั่งดึงข้อมูล).<br>
ตัวดึงตัวอักษรรอการเชื่อมเข้ากับของทั่งสองท่อ หลังจากนั่นส่งคำสั่งไปยังข้อมูลนั่น (เช่น แสดงผลข้อมูล เป็นต้น) และทำให้ข้อมูลส่งผ่านต่อมาออกมาได้ถูกต้อง<br>
ข้อมูลบางอย่างเกี่ยวกับการเชื่อมจะถูกแลกเปลี่ยนผ่านความทรงจำของระบบ (shared memory)
<br>
ตัวอักษรที่ฐานโปรแกรมรับผ่านท่อจะถูกแปลงเล็กน้อยก่อนที่จะแสดงผ่าน GUI <br>
สุดท้ายแล้ว GUI จะส่งข้อมูลตัวอักษรไปยังส่วนขยายต่างๆก่อนที่จะแสดงให้เห็นในหน้าจอ

## นักพัฒนา

ถ้าหากคุณมีรายชื่ออยู่ด้านล่างและต้องการให้เปลี่ยนสามารถติดต่อเจ้าของได้
- Textractor ถูกเขียนขึ้นมาโดย [Me](https://github.com/Artikash) และได้รับความช่วยเหลือของ
  - [DoumanAsh](https://github.com/DoumanAsh)
  - [Niakr1s](https://github.com/Niakr1s)
  - [tinyAdapter](https://github.com/tinyAdapter)
- Spanish แปลโดย [scese250](https://github.com/scese250)
- Turkish แปลโดย niisokusu
- Simplified Chinese แปลโดย [tinyAdapter](https://github.com/tinyAdapter)
- Russian แปลโดย [TokcDK](https://github.com/TokcDK)
- Indonesian แปลโดย [Hawxone](https://github.com/Hawxone)
- Portuguese แปลโดย [TsumiHokiro](https://github.com/TsumiHokiro)
- Thai แปลโดย [AzmaDoppler](https://github.com/azmadoppler)
- ITHVNR updated by [mireado](https://github.com/mireado), [Eguni](https://github.com/Eguni), and [IJEMIN](https://github.com/IJEMIN)
- ITHVNR originally สร้างโดย [Stomp](http://www.hongfire.com/forum/member/325894-stomp)
- VNR engine สร้างโดย [jichi](https://archive.is/prJwr)
- ITH ถูกอัพเดทโดย [Andys](https://github.com/AndyScull)
- ITH ถูกสร้างขึ้นโดย [kaosu](http://www.hongfire.com/forum/member/562651-kaosu)
- Locale Emulator library สร้างโดย [xupefei](https://github.com/xupefei)
- MinHook library สร้างโดย [TsudaKageyu](https://github.com/TsudaKageyu)

## สุดท้ายนี้ขอขอบคุณ

- ทุกคนที่ส่งคำแนะนำ หรือ รายงานปัญหาในหน้า issues!