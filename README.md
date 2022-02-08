# administration-script-templates
Python scripts for external communication with something

- email_to_admins - send email in cron
- script - script which do something


# cron config
```
SEMAIL="/home/Chepelev_VS/email_to_admins/script_e.py"
# redirect stdout to log, pipe stderr to email
/20    *        /home/Chepelev_VS/souz/souz_script.py 2>&1 >/dev/null | $SEMAIL "Ошибка обмена с СОЮЗ б-ом шлюз"
```
