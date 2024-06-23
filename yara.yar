rule Spotless
{
    meta:
      name = "Spotless"
    strings:
        $my_text_string = "Spotless_Click"
        $my_text_string2 = "guna2GradientButton1_Click"
        $my_text_string3 = "download_Click"
    condition:
        $my_text_string and $my_text_string2 and $my_text_string3
}

rule Royal
{
    meta:
      name = "Royal"
    strings:
        $my_text_string = "guna2Button7_Click"
        $my_text_string2 = "label3_Click"
        $my_text_string3 = "dllinj_Tick"
        $my_text_string4 = "siticonePictureBox1_Click"
        $my_text_string5 = "L3CwOwWW"
    condition:
        $my_text_string and $my_text_string2 and $my_text_string3 and $my_text_string4 and $my_text_string5
}
