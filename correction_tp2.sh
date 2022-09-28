#!/bin/bash
codemoodlehash="b'$1'0fe206f9"
chmod -R 777 trace_files/
grepd=$(babeltrace trace_files/ | grep -e "grpc_tracing:" |wc -l)
echo "############################################"
echo "# Correction INF8480 TP2 Hiver 2022 V7.0 #"
echo "############################################"
echo "Résutat :"
if [ $grepd -ge 3 ]
	then
		r=$(echo -n $codemoodlehash | base64)
		echo "hash ok"
		echo "Tp vérifé ! Votre hash unique est : $r"
	else
		echo "Le script n'a pas trouve la trace d'execution de votre application"
fi

