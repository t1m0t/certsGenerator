import datetime


def checkConf(generalConf: dict):
    # check if no redundant certs names
    certs = generalConf["certs"]
    names: dict = {}
    for cert in certs:
        if cert["name"] in names.keys():
            names[cert["name"]] += 1
        else:
            names[cert["name"]] = 1
    for k, v in names.items():
        if v > 1:
            raise ValueError(f"Configuration file error: {k} appears {v} times")

    # check not_valid_before not_valid_after
    for certConf in certs:
        certConf = certConf["conf"]
        if certConf["not_valid_before"] == "now":
            nvb = datetime.datetime.utcnow()
        elif isinstance(int(), certConf["not_valid_before"]) or isinstance(
            int, certConf["not_valid_after"]
        ):
            nvb = datetime.datetime.utcnow() + datetime.timedelta(
                days=certConf["not_valid_before"]
            )
        else:
            raise ValueError(f'invalid value from {nvb}, should be of int or "now"')
