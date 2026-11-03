"""Reply templates in easy language: English, Bahasa Malaysia, Chinese (Simplified), Manglish.

Wording is a first draft written for readability testing. Have native speakers from the
target community review and simplify it before any real-user pilot.
"""

from __future__ import annotations

from .triage import AMBER, GREENISH, RED, UNSURE, Result

LANGS = ("en", "ms", "zh", "manglish")

HEAD = {
    RED: {
        "en": "This looks like a scam.",
        "ms": "Ini nampak seperti penipuan.",
        "zh": "这看起来是诈骗。",
        "manglish": "This one look like scam, ah.",
    },
    AMBER: {
        "en": "Be careful. I see warning signs.",
        "ms": "Berhati-hati. Saya nampak tanda amaran.",
        "zh": "请小心，我看到一些可疑的地方。",
        "manglish": "Careful ah. I see some warning signs.",
    },
    GREENISH: {
        "en": "I do not see warning signs, but I cannot be 100% sure.",
        "ms": "Saya tak nampak tanda amaran, tapi saya tak boleh pastikan 100%.",
        "zh": "我没有看到明显的可疑迹象，但我不能百分之百确定。",
        "manglish": "I don't see warning signs, but cannot be 100% sure lah.",
    },
    UNSURE: {
        "en": "I cannot check this properly.",
        "ms": "Saya tak dapat semak ini dengan betul.",
        "zh": "我没办法好好检查这个。",
        "manglish": "I cannot check this one properly.",
    },
}

REASONS = {
    "blocklist": {
        "en": "This number or website is on a confirmed scam list.",
        "ms": "Nombor atau laman web ini ada dalam senarai penipuan yang disahkan.",
        "zh": "这个号码或网站在已确认的诈骗名单上。",
        "manglish": "This number or website is on the confirmed scam list.",
    },
    "safe_account": {
        "en": "Police and banks never ask you to move money to a safe account.",
        "ms": "Polis dan bank tak akan suruh pindah duit ke akaun selamat.",
        "zh": "警察和银行不会叫你把钱转到安全账户。",
        "manglish": "Police and bank never ask you move money to safe account one.",
    },
    "otp_request": {
        "en": "Someone is asking for your OTP, PIN or password. Never give these.",
        "ms": "Ada orang minta OTP, PIN atau kata laluan anda. Jangan bagi.",
        "zh": "有人要你的验证码、密码。千万不要给。",
        "manglish": "They ask for your OTP, PIN or password. Never give lah.",
    },
    "lookalike": {
        "en": "The website address copies a real bank or office, but it is not the real one.",
        "ms": "Alamat laman web ini meniru bank atau pejabat sebenar, tapi bukan yang asli.",
        "zh": "这个网址假装是真的银行或机构，但不是真的。",
        "manglish": "The website address copy a real bank, but it is not the real one.",
    },
    "apk": {
        "en": "It asks you to install an app file. Fake apps can steal your bank details.",
        "ms": "Ia suruh pasang fail aplikasi. Aplikasi palsu boleh curi maklumat bank anda.",
        "zh": "它要你安装一个应用文件。假应用会偷你的银行资料。",
        "manglish": "It ask you install an app file. Fake app can steal your bank details.",
    },
    "authority": {
        "en": "It says it is from the police, court, tax office or similar.",
        "ms": "Ia kata ia dari polis, mahkamah, LHDN atau pihak berkuasa lain.",
        "zh": "它说自己是警察、法院、税务局之类的机构。",
        "manglish": "They say they are police, court or government office.",
    },
    "money_transfer": {
        "en": "It asks you to pay or transfer money.",
        "ms": "Ia suruh anda bayar atau pindah duit.",
        "zh": "它要你付款或转账。",
        "manglish": "They ask you pay or transfer money.",
    },
    "investment": {
        "en": "It promises big, safe profits. Real investments cannot promise that.",
        "ms": "Ia janji untung besar dan selamat. Pelaburan sebenar tak boleh janji macam tu.",
        "zh": "它保证高回报。真正的投资不可能保证赚钱。",
        "manglish": "They promise big safe profit. Real investment cannot promise like that.",
    },
    "prize": {
        "en": "It says you won a prize you did not enter for.",
        "ms": "Ia kata anda menang hadiah yang anda tak sertai.",
        "zh": "它说你中了奖，但你根本没参加。",
        "manglish": "They say you win a prize but you never join anything.",
    },
    "punycode": {
        "en": "The website address uses tricky letters to look real.",
        "ms": "Alamat laman web ini guna huruf pelik supaya nampak asli.",
        "zh": "这个网址用了特殊字符来假装真的。",
        "manglish": "The website address use tricky letters to look real.",
    },
    "ip_link": {
        "en": "The link is just numbers, not a real company name.",
        "ms": "Pautan ini hanya nombor, bukan nama syarikat sebenar.",
        "zh": "这个链接只是一串数字，不是真正的公司名称。",
        "manglish": "The link is only numbers, not a real company name.",
    },
    "shortener": {
        "en": "The link is shortened, so you cannot see where it goes.",
        "ms": "Pautan ini dipendekkan, jadi anda tak nampak ia pergi ke mana.",
        "zh": "这个链接被缩短了，你看不出它通向哪里。",
        "manglish": "The link is shortened, so cannot see where it goes.",
    },
    "odd_tld": {
        "en": "The website ending is one that scammers often use.",
        "ms": "Hujung alamat laman web ini sering digunakan penipu.",
        "zh": "这个网址的结尾常被骗子使用。",
        "manglish": "The website ending is one scammers always use.",
    },
    "job": {
        "en": "It offers easy work from home or part-time pay.",
        "ms": "Ia tawar kerja mudah dari rumah atau kerja sambilan.",
        "zh": "它提供轻松的在家兼职工作。",
        "manglish": "They offer easy work-from-home or part-time job.",
    },
    "urgency": {
        "en": "It tries to rush you.",
        "ms": "Ia cuba menggesa anda.",
        "zh": "它在催你快点决定。",
        "manglish": "They try to rush you.",
    },
    "parcel": {
        "en": "It talks about a parcel delivery.",
        "ms": "Ia bercakap tentang penghantaran bungkusan.",
        "zh": "它提到包裹快递。",
        "manglish": "They talk about parcel delivery.",
    },
    "link": {
        "en": "It has a link. Do not click it.",
        "ms": "Ia ada pautan. Jangan klik.",
        "zh": "里面有链接。不要点。",
        "manglish": "There is a link. Don't click.",
    },
}

STEPS = {
    "en": [
        "Stop. Do not click, reply, pay or give any number.",
        "Check. Call your bank using the number on the back of your card, or ask your family.",
        "Report and block. Tell the official scam hotline, then block the number.",
    ],
    "ms": [
        "Berhenti. Jangan klik, balas, bayar atau bagi sebarang nombor.",
        "Semak. Telefon bank anda guna nombor di belakang kad, atau tanya keluarga.",
        "Lapor dan sekat. Beritahu talian hotline penipuan rasmi, kemudian sekat nombor itu.",
    ],
    "zh": [
        "先停下来。不要点链接、不要回复、不要付钱，也不要给任何号码。",
        "再确认。用银行卡背面的号码打给银行，或者问问家人。",
        "举报并拉黑。告诉官方的防骗热线，然后拉黑这个号码。",
    ],
    "manglish": [
        "Stop first. Don't click, reply, pay or give any number.",
        "Check. Call your bank using the number at the back of your card, or ask your family.",
        "Report and block. Tell the official scam hotline, then block the number.",
    ],
}

CAUTION = {
    "en": "Do not click or pay until your bank or your family confirms.",
    "ms": "Jangan klik atau bayar sehingga bank atau keluarga anda mengesahkan.",
    "zh": "在银行或家人确认之前，不要点链接，也不要付钱。",
    "manglish": "Don't click or pay until your bank or family confirm first.",
}

RETRY = {
    "en": "Please send me the whole message, number or link again.",
    "ms": "Sila hantar semula keseluruhan mesej, nombor atau pautan itu.",
    "zh": "请把整条消息、号码或链接再发一次给我。",
    "manglish": "Please send the whole message, number or link again.",
}

HOTLINE = {
    "en": "Official hotline: {name}, {phone}.",
    "ms": "Talian rasmi: {name}, {phone}.",
    "zh": "官方热线：{name}，{phone}。",
    "manglish": "Official hotline: {name}, {phone}.",
}

REASONS["risky_file"] = {
    "en": "It is a program file, not a normal document or picture. It can harm your phone or computer.",
    "ms": "Ini fail program, bukan dokumen atau gambar biasa. Ia boleh merosakkan telefon atau komputer anda.",
    "zh": "这是一个程序文件，不是普通的文档或图片。它可能伤害你的手机或电脑。",
    "manglish": "This is a program file, not normal document or picture. It can harm your phone or computer.",
}
REASONS["double_extension"] = {
    "en": "The file name pretends to be a document, but it is really a program.",
    "ms": "Nama fail ini berpura-pura jadi dokumen, tetapi sebenarnya program.",
    "zh": "这个文件名假装是文档，其实是个程序。",
    "manglish": "The file name pretend to be a document, but actually it is a program.",
}

EMERGENCY = {
    "en": (
        "Thank you for telling me. This can happen to anyone. Let us act fast.\n"
        "1. Call your bank now. Use the number on the back of your card. Ask them to stop or freeze the transfer.\n"
        "2. Then call the official scam hotline.\n"
        "3. If you installed an unknown app, or someone controlled your phone, turn on aeroplane mode and do not type any password. Take the phone to your bank or telco counter.\n"
        "4. Later, change your passwords from a safe phone and make a police report.\n"
        "The sooner you call the bank, the better the chance to stop the money."
    ),
    "ms": (
        "Terima kasih kerana beritahu saya. Ini boleh berlaku pada sesiapa sahaja. Mari kita bertindak cepat.\n"
        "1. Telefon bank anda sekarang. Guna nombor di belakang kad. Minta mereka hentikan atau bekukan pemindahan itu.\n"
        "2. Kemudian telefon talian hotline penipuan rasmi.\n"
        "3. Jika anda pasang aplikasi yang tidak dikenali, atau ada orang kawal telefon anda, buka mod kapal terbang dan jangan taip sebarang kata laluan. Bawa telefon ke kaunter bank atau telco anda.\n"
        "4. Kemudian, tukar kata laluan dari telefon yang selamat dan buat laporan polis.\n"
        "Semakin cepat anda telefon bank, semakin besar peluang untuk menghentikan wang itu."
    ),
    "zh": (
        "谢谢你告诉我。这种事谁都可能遇到。我们要赶快行动。\n"
        "1. 马上打电话给银行。用银行卡背面的号码。请他们停止或冻结这笔转账。\n"
        "2. 然后打给官方的防骗热线。\n"
        "3. 如果你装了不明应用，或者有人控制了你的手机，请开启飞行模式，不要输入任何密码，把手机带到银行或电信公司柜台。\n"
        "4. 之后用安全的手机更改密码，并去报警。\n"
        "越早打给银行，越有机会拦住这笔钱。"
    ),
    "manglish": (
        "Thanks for telling me. This can happen to anyone one. Let's act fast.\n"
        "1. Call your bank now. Use the number at the back of your card. Ask them stop or freeze the transfer.\n"
        "2. Then call the official scam hotline.\n"
        "3. If you installed some strange app, or somebody control your phone, switch on aeroplane mode and don't type any password. Bring the phone to the bank or telco counter.\n"
        "4. After that, change your passwords from a safe phone and make a police report.\n"
        "The faster you call the bank, the better the chance to stop the money."
    ),
}

WELCOME = (
    "Hello! I am Scam Helper. Send me a message, number, link or file name that you are not sure about, "
    "and I will tell you if it looks like a scam.\n"
    "Hai! Saya Scam Helper. Hantar mesej, nombor, pautan atau nama fail yang anda ragu-ragu, "
    "dan saya akan beritahu sama ada ia nampak seperti penipuan.\n"
    "你好！我是 Scam Helper。把你不确定的消息、号码、链接或文件名发给我，我会告诉你它看起来像不像诈骗。\n"
    "Never share your OTP, PIN or password with anyone, including me."
)

UNSUPPORTED = (
    "I cannot read voice notes or pictures yet. Please type the message, number or link.\n"
    "Saya belum boleh baca nota suara atau gambar. Sila taip mesej, nombor atau pautan itu.\n"
    "我暂时还看不了语音和图片。请把消息、号码或链接打字发给我。"
)

MAX_REASONS = 2


def render(result: Result, lang: str = "en", contact: dict | None = None, voice: bool = False) -> str:
    """Build the reply. Voice mode drops numbering so it reads naturally aloud."""
    if lang not in LANGS:
        lang = "en"
    lines = [HEAD[result.label][lang]]

    if result.label in (RED, AMBER):
        for code in result.codes[:MAX_REASONS]:
            if code in REASONS:
                lines.append(REASONS[code][lang])
        steps = list(STEPS[lang])
        if contact:
            steps.append(HOTLINE[lang].format(name=contact["name"], phone=contact["phone"]))
        lines += steps if voice else [f"{i}. {s}" for i, s in enumerate(steps, 1)]
    elif result.label == GREENISH:
        lines.append(CAUTION[lang])
    else:
        lines.append(RETRY[lang])
    return (" " if voice else "\n").join(lines)
