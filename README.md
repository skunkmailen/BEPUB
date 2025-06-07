# BEPUB

### :warning: Fungerar endast på böcker som du har lånat via Biblio.
\
När en bok laddas via Biblios hemsida så laddas en .EPUB-fil som sedan avkrypteras i webbläsaren.  
Tampermonkey-skriptet snappar upp länken till .EPUB-filen, din personliga nyckel till boken samt ditt användar-ID.  
Detta är informationen som krävs för att kunna generera en upplåst .EPUB-fil.  

## Installation
### <ins>Tampermonkey</ins>
1) Installera Tampermonkey.
2) Lägg till skriptet ("Biblio EPUB-1.1.user.js").
3) Ladda boken i webbläsaren via Biblios hemsida genom att öppna den och trycka på "Läs".  
4) När boken har laddat färdigt så ska rutan dyka upp.  
   Uppdatera sidan (F5) om den inte gör det.
6) Tryck på knappen för att "kopiera info".
   
![bild](https://github.com/user-attachments/assets/11e61e82-529b-47c8-87ba-b6b3ec53a14a)


### <ins>Python-skript (.py)</ins>
1) Installera Python.
2) Skapa en mapp och ladda ner filerna härifrån, t.ex. "C:\ebok".
3) Via "Kommandotolken"/CMD, navigera till mappen "cd C:\ebok".
4) Kör kommandot "pip install requirements.txt"
5) Kör kommandot "python decrypto.py"
6) Klistra in info från Tampermonkey-skriptet.
7) Välj mapp och tryck på "Start".

### <ins>Python-skript (.exe för Windows) - Release</ins>
1) Ladda ner och kör .exe-filen från 'Releases'.
3) Klistra in info från Tampermonkey-skriptet.
4) Välj mapp och tryck på "Start".

### <ins>Python-skript (.exe för Windows) - PyInstaller</ins>
(Om man föredrar att skapa .exe-filen själv.)

1) Skapa en mapp och ladda ner filerna härifrån, t.ex. "C:\ebok".
2) Via "Kommandotolken"/CMD, navigera till mappen "cd C:\ebok".
3) Kör kommandot "pip install requirements.txt"
4) Kör kommandot "pip install pyinstaller"
5) Kör kommandot "pyinstaller --noconsole --onefile decrypto.py"
6) Exe-fil skapas och hamnar under "c:\ebok\dist".