#!/bin/bash

HASH=("sha1" "sha224" "sha256" "sha384" "sha512" )
CURV=("192" "224" "256" "384" "521" )
RSA=("512" "1024" "2048" "4096" )
PBE_ALGS=("PBE-SHA1-3DES" "PBE-SHA1-2DES" )
CIPHER=("des3" "aes128" "aes192" "aes256" )
FLAG=$1
TYPE=$2

if [ $# -eq 0 ] || [ "${FLAG}" = "-h" ] || [ "${FLAG}" = "--help" ] ; then
	cat <<EOF
	Usage options: 

	-grc    	| --generate-root-certificates	generate ecdsa certificates. Params: ecdsa, rsa. Example: -grc rsa
	-gc     	| --generate-certificates-ecdsa	generate certificates. Params: ecdsa, rsa. Example: -gc ecdsa
	-gs     	| --generate-storage-ecdsa	generate pkcs12 storage. Current version can do ecdsa only.
	-d   		| --delete			delete all generated certificates
	-h   		| --help			help


	EXAPLE USAGE:
	./osslHelpUtil -grc ecdsa
	./osslHelpUtil -gc rsa
	./osslHelpUtil -d



	NOTE: for ./osslHelpUtil -grc rsa you need xdotool to avoid multiple enter PASS PEM PHRASE.
	sudo apt-get install xdotool




EOF
fi

if [ "${FLAG}" = "-grc" ] || [ "${FLAG}" = "--generate-root-certificates" ] ; then
	for i in ${!HASH[*]}
	do
		if [ "${TYPE}" = "ecdsa" ] ; then
			for j in ${!CURV[*]}
			do
				{
					openssl ecparam -name secp${CURV[$j]}r1 -genkey  -out private-key.pem
					openssl req -new -x509 -key private-key.pem -${HASH[$i]} -out cert_ecdsa_${CURV[$j]}_with_${HASH[$i]}.crt  -days 1730 -subj "/ST=Dnepr"
					rm private-key.pem
				} &> /dev/null
			done
		fi
		if [ "${TYPE}" = "rsa" ] ; then
			for j in ${!RSA[*]}
			do
				{
					openssl req -x509 -${HASH[$i]} -newkey rsa:${RSA[$i]} -out cert_rsa_${RSA[$j]}_with_${HASH[$i]}.crt -days 1730 -subj "/ST=Dnepr"
					xdotool key h e l l o;
					xdotool key KP_Enter;
					xdotool key h e l l o;
					xdotool key KP_Enter;
					rm private-key.pem
				} &> /dev/null
			done
		fi
	done
fi

if [ "${FLAG}" = "-gc" ] || [ "${FLAG}" = "--generate-certificates" ] ; then
	#Создаем рутовый сертификат
	if [ "${TYPE}" = "ecdsa" ] ; then
		openssl ecparam -name secp521r1 -genkey -out CAkey.key
		openssl req -new -x509 -key CAkey.key -sha512 -out CAcert.crt -days 1730 -subj "/ST=Dnepr"
	fi
	if [ "${TYPE}" = "rsa" ] ; then
		#Создаем рутовый сертификат
		openssl req -x509 -sha512 -newkey rsa:4096 -keyout CAkeyWithPassPhrase.key -out CAcert.crt -days 1730 -subj "/ST=Dnepr"

		#Избавляемся от pass phrase
		openssl rsa -in CAkeyWithPassPhrase.key -out CAkey.key
	fi

	for i in ${!HASH[*]}
	do
		if [ "${TYPE}" = "ecdsa" ] ; then
			for j in ${!CURV[*]}
			do
				{
					#Создаем ключ
					openssl ecparam -name secp${CURV[$j]}r1 -genkey -out private-key.pem
					#Создаем запрос на выпуск сертификата
					openssl req -new -${HASH[$i]} -key private-key.pem -out cert_ecdsa_${CURV[$j]}_with_${HASH[$i]}.csr -subj "/ST=Dnepr"
					#Выпускаем сертификат на основе запроса, подписаный корневым
					openssl x509 -req -CA CAcert.crt -CAkey CAkey.key -CAcreateserial -in cert_ecdsa_${CURV[$j]}_with_${HASH[$i]}.csr -out cert_ecdsa_${CURV[$j]}_with_${HASH[$i]}.crt -days 365
					rm private-key.pem
					#rm cert_ecdsa_${CURV[$j]}_with_${HASH[$i]}.csr
				} &> /dev/null
			done
		fi
		if [ "${TYPE}" = "rsa" ] ; then
			for j in ${!RSA[*]}
			do
				{
					#Создаем ключ
					openssl req -out cert_rsa_${RSA[$j]}_with_${HASH[$i]}.csr -new -newkey rsa:${RSA[$j]} -nodes -keyout private-key.pem -subj "/ST=Dnepr"
					#Создаем запрос на выпуск сертификата
					openssl req -new -${HASH[$i]} -key private-key.pem -out cert_rsa_${RSA[$j]}_with_${HASH[$i]}.csr -subj "/ST=Dnepr"
					#Выпускаем сертификат на основе запроса, подписаный корневым
					openssl x509 -req -CA CAcert.crt -CAkey CAkey.key -CAcreateserial -in cert_rsa_${RSA[$j]}_with_${HASH[$i]}.csr -out cert_rsa_${RSA[$j]}_with_${HASH[$i]}.crt -days 365
					rm private-key.pem
					rm cert_rsa_${RSA[$j]}_with_${HASH[$i]}.csr
				} &> /dev/null
			done
		fi
	done
fi

if [ "${FLAG}" == "-d" ] || [ "${FLAG}" == "--delete" ] ; then
	{
		rm CAkey.key
		rm CAcert.crt
		rm CAcert.srl
		rm CAkeyWithPassPhrase.key
		rm privkey.pem
	} &> /dev/null

	for i in ${!HASH[*]}
	do
		for j in ${!CURV[*]}
		do
			{
				rm cert_ecdsa_${CURV[$j]}_with_${HASH[$i]}.crt
			} &> /dev/null
		done
	done
	for i in ${!HASH[*]}
	do
		for j in ${!RSA[*]}
		do
			{
				rm cert_rsa_${RSA[$j]}_with_${HASH[$i]}.crt
			} &> /dev/null
		done
	done
	for i in ${!HASH[*]}
	do
		for j in ${!CURV[*]}
		do
			{
				rm pkcs12_${CURV[$j]}_${HASH[$i]}_${HASH[$i]}_${CIPHER[0]}_${PBE_ALGS[0]}.p12
			} &> /dev/null
		done
	done
	for i in ${!PBE_ALGS[*]}
	do
		for j in ${!CIPHER[*]}
		do
			{
				rm pkcs12_${CURV[3]}_${HASH[3]}_${HASH[3]}_${CIPHER[$j]}_${PBE_ALGS[$i]}.p12
			} &> /dev/null
		done
	done
fi

if [ "${FLAG}" == "-gs" ] || [ "${FLAG}" == "--generate-storage" ] ; then
	if [ "${TYPE}" = "ecdsa" ] ; then
		for i in ${!HASH[*]}
		do
			for j in ${!CURV[*]}
			do
						{
							openssl ecparam -name secp${CURV[$j]}r1 -genkey  -out private-key.pem
							openssl req -new -x509 -key private-key.pem -${HASH[$i]} -out cert_ecdsa_${CURV[$j]}_with_${HASH[$i]}.crt  -days 1730 -subj "/ST=Dnepr"
							openssl pkcs12 -export -inkey private-key.pem -in cert_ecdsa_${CURV[$j]}_with_${HASH[$i]}.crt -${CIPHER[0]} -macalg ${HASH[$k]} -keypbe ${PBE_ALGS[0]} -certpbe ${PBE_ALGS[0]} -out pkcs12_${CURV[$j]}_${HASH[$i]}_${HASH[$i]}_${CIPHER[0]}_${PBE_ALGS[0]}.p12 -passout pass:123456
							rm private-key.pem
							rm cert_ecdsa_${CURV[$j]}_with_${HASH[$i]}.crt 
						} &> /dev/null
			done
		done
		for i in ${!PBE_ALGS[*]}
		do
			for j in ${!CIPHER[*]}
			do
						{
							openssl ecparam -name secp${CURV[$j]}r1 -genkey  -out private-key.pem
							openssl req -new -x509 -key private-key.pem -${HASH[3]} -out cert_ecdsa_${CURV[3]}_with_${HASH[3]}.crt  -days 1730 -subj "/ST=Dnepr"
							openssl pkcs12 -export -inkey private-key.pem -in cert_ecdsa_${CURV[3]}_with_${HASH[3]}.crt -${CIPHER[$j]} -macalg ${HASH[3]} -keypbe ${PBE_ALGS[$i]} -certpbe ${PBE_ALGS[$i]} -out pkcs12_${CURV[3]}_${HASH[3]}_${HASH[3]}_${CIPHER[$j]}_${PBE_ALGS[$i]}.p12 -passout pass:123456
							rm private-key.pem
							rm cert_ecdsa_${CURV[$j]}_with_${HASH[$i]}.crt 
						} &> /dev/null
			done
		done
	fi
fi
