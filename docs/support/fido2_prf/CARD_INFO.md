# Card and Reader Info (examples)

- Reader: HID Global OMNIKEY 5422 Smartcard Reader (contact slot)
- PC/SC: Select the slot that shows an ATR when a card is inserted.
- macOS: Use `pyscard` to list readers and check ATRs.

Quick reader probe (Python):

```
python - <<'PY'
from smartcard.System import readers
from smartcard.Exceptions import CardConnectionException
for r in readers():
    print('Reader:', r)
    try:
        c=r.createConnection(); c.connect(); print(' ATR:', bytes(c.getATR()).hex()); c.disconnect()
    except CardConnectionException as e:
        print(' No card in this reader:', e)
PY
```

Notes:
- If two OMNIKEY slots appear, choose the one that returns a valid ATR.
- `gp.jar -r "<Reader Name>"` must match the exact PC/SC reader string.
- If you see “Invalid protocol in transmit” in other tools, force T=1.
