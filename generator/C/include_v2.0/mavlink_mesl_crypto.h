
/*
Add␣crypto␣support␣for␣MAVLink␣C␣protocol␣2.0.
␣␣Define␣'MESL_CRYPTO'␣for␣crypto␣support,␣when␣using.
␣␣Implement␣some␣functions␣for␣crypto␣support,␣when␣using.
␣␣␣␣'mavlink_mesl_crypto_condition'.
␣␣␣␣'mavlink_mesl_encrypt'.
␣␣␣␣'mavlink_mesl_decrypt'.
Add␣some␣function␣for␣MAVLink␣debugging.
␣␣Define␣'MESL_+MAVLINK_DEBUG'␣for␣debugging␣support,␣when␣using.
␣␣␣␣Implement␣'mavlink_mesl_parse_result'.
Fix␣some␣code␣for␣MAVLink␣parsing.
␣␣To␣use␣fixed␣parsing␣way,␣define␣'MESL_MAVLINK_PARSE_FIX'.
␣␣This␣will␣be␣automatically␣enabled␣if␣need,
␣␣␣␣like␣when␣using␣crypto␣support.
*/



#ifdef MESL_CRYPTO
#ifndef MESL_MAVLINK_PARSE_FIX
#define MESL_MAVLINK_PARSE_FIX
#endif
#endif // #ifdef MESL_CRYPTO

#ifdef MESL_INTEGRITY
#ifndef MESL_MAVLINK_PARSE_FIX
#define MESL_MAVLINK_PARSE_FIX
#endif
#endif // #ifdef MESL_INTEGRITY



#ifdef MAVLINK_USE_CXX_NAMESPACE
namespace mavlink {
#endif



#ifdef MESL_CRYPTO

// @brief  Function to decide if MAVLink payload should be encrypted.
//         Program that use MAVLink should implement this function.
// @param  'len': payload length (can be 0).
// @return 'MESL_CRYPTO_METHOD_XXX' (true),
//           if MAVLink payload should be encrypted.
//         Zero otherwise.
MAVLINK_HELPER uint8_t mavlink_mesl_crypto_condition(
		mavlink_status_t* status,
		uint32_t msgid,
		uint8_t system_id,
		uint8_t component_id,
		const char *payload,
		uint8_t len
		);

// @brief  Function to encrypt MAVLink payload.
//         Program that use MAVLink should implement this function.
// @param  'crypto_method': method for encryption,
//           value should be 'MESL_CRYPTO_METHOD_XXX'.
// @param  'len': payload length (can be 0).
// @return Payload length after encryption.
// @note   "input_len == 0 && output_len == 0",
//           will be considered as non-encryption.
//         But, "input len != 0 && output_len == 0",
//           or "output_len < 0 || output_len > maxlen",
//           will be considered as error,
//           MAVLink frame will be sent with zero payload length,
//           and receiving side can report error,
//           because the length is zero but encryption iflag is set.
MAVLINK_HELPER int32_t mavlink_mesl_encrypt(
		uint8_t crypto_method,
		const char *src,
		char *dst,
		uint8_t len,
		uint8_t maxlen
		);

// @brief  Function to decrypt MAVLink payload.
//         Program that use MAVLink should implement this function.
// @param  'crypto_method': method for decryption,
//           value can be 'MESL_CRYPTO_METHOD_XXX'.
//         For invalid 'crypto_method',
//           this function should return '-1'.
// @param  'len': payload length.
//         If 'len' is zero,
//           this function should return '-1'.
// @return Payload length after decryption (zero is valid result).
//         If "output_len < 0 || output_len > maxlen",
//           will be considered as error,
//           one example is for invalue 'crypto_method'.
MAVLINK_HELPER int32_t mavlink_mesl_decrypt(
		uint8_t crypto_method,
		const char *src,
		char *dst,
		uint8_t len,
		uint8_t maxlen
		);

#endif // #ifdef MESL_CRYPTO

#ifdef MESL_MAVLINK_DEBUG

// @brief  Function for debug MAVLink frame parsing result.
MAVLINK_HELPER void mavlink_mesl_parse_result(
		const mavlink_message_t* rxmsg,
		const mavlink_status_t* status
		);

#endif // #ifdef MESL_MAVLINK_DEBUG




// ---------------------------------------------------------------------
// Internal functions for modifing code of 'mavlink_helpers.h'
// 'mesl_edit_xxx'
// Placing this function code into original code is also natural way.
//   Reason:
//     The hierarchy role of edited code itself.
//     Edited code requires local variables editing of original code.
//     Some duplicated code like condition check.
// Be careful with 'pointer' params.
// ---------------------------------------------------------------------

#ifdef MESL_CRYPTO

// Copy some function declaration first from 'mavlink_helpers.h'

MAVLINK_HELPER uint8_t _mav_trim_payload(const char *payload, uint8_t length);
static inline void _mav_parse_error(mavlink_status_t *status);


MAVLINK_HELPER void mesl_edit_mav_encrypt(
		mavlink_status_t* status,
		uint32_t msgid,
		uint8_t * len_p,
		uint8_t system_id,
		uint8_t component_id,
		uint8_t * incompat_flags_p,
		const char *payload_src,
		char *payload_dst
) {
	uint8_t mesl_crypto_method;
	int32_t encrypted_len;
	bool mavlink1 = (status->flags & MAVLINK_STATUS_FLAG_OUT_MAVLINK1) != 0;
	if (mavlink1) {
		// No support for mavlink protocol v1.0
		return;
	}
	// crypto condition check.
	if (status) {
		mesl_crypto_method = mavlink_mesl_crypto_condition(
			status,
			msgid,
			system_id,
			component_id,
			payload_src,
			*len_p
			);
		mesl_crypto_method = (mesl_crypto_method & BITMASK_MESL_CRYPTO_METHOD);
		// set flag
		*incompat_flags_p &= ~
			((uint8_t)MAVLINK_IFLAG_MESL_CRYPTO_METHOD);
		*incompat_flags_p |= (mesl_crypto_method << BITSHIFT_MESL_CRYPTO_METHOD);
	}
	else {
		mesl_crypto_method = (*incompat_flags_p >> BITSHIFT_MESL_CRYPTO_METHOD);
	}
	// encryption
	if (mesl_crypto_method != (uint8_t)0) {
		encrypted_len = mavlink_mesl_encrypt(
				mesl_crypto_method,
				payload_src,
				payload_dst,
				*len_p,
				MAVLINK_MAX_PAYLOAD_LEN
				);
		if (*len_p == (uint8_t)0 && encrypted_len == (int32_t)0) {
			// Zero length to zero length encryption.
			// Consider as non-encryption.
			*incompat_flags_p &= ~
				((uint8_t)MAVLINK_IFLAG_MESL_CRYPTO_METHOD);
			*len_p = (uint8_t)0;
		}
		else if (encrypted_len <= (int32_t)0 ||
				encrypted_len > (int32_t)MAVLINK_MAX_PAYLOAD_LEN) {
			// zero length is error now (for rx side).
			*len_p = (uint8_t)0;
		}
		else {
			*len_p = (uint8_t)encrypted_len;
		}
	}
}

MAVLINK_HELPER void mesl_edit_mav_encrypt_case1(
		mavlink_status_t* status,
		mavlink_message_t* msg
) {
	mesl_edit_mav_encrypt(
			status,
			msg->msgid,
			&(msg->len),
			msg->sysid,
			msg->compid,
			&(msg->incompat_flags),
			_MAV_PAYLOAD(msg),
			(char*)status->mesl_crypto_buf
			);
	if (msg->incompat_flags & MAVLINK_IFLAG_MESL_CRYPTO_METHOD) {
		memcpy(
				(char*)status->mesl_crypto_buf,
				_MAV_PAYLOAD(msg),
				msg->len);
		msg->mesl_curpl_encrypted = (uint8_t)1;
	}
}

MAVLINK_HELPER void mesl_edit_mav_encrypt_case2(
		mavlink_status_t* status,
		uint32_t msgid,
		uint8_t * len_p,
		uint8_t system_id,
		uint8_t component_id,
		uint8_t * incompat_flags_p,
		const char* * payload_p // Should be the pointer of pointer
) {
	mesl_edit_mav_encrypt(
			status,
			msgid,
			len_p,
			system_id,
			component_id,
			incompat_flags_p,
			(const char *) * payload_p,
			(char*)status->mesl_crypto_buf
			);
	if ((*incompat_flags_p) & MAVLINK_IFLAG_MESL_CRYPTO_METHOD) {
		*payload_p = (const char*)(status->mesl_crypto_buf);
	}
}

MAVLINK_HELPER void mesl_edit_mav_encrypt_case3(
		const mavlink_message_t* msg,
		uint8_t * len_p,
		uint8_t * incompat_flags_p,
		char * payload_dst,
		const char* * payload_result_addr // Should be the pointer of pointer
) {
	if (
			!((*incompat_flags_p) & MAVLINK_IFLAG_MESL_CRYPTO_METHOD)
	) {
		// CASE OF: normal MAVLink frame (no encryption).
		*len_p = _mav_trim_payload(_MAV_PAYLOAD(msg), *len_p);
		return;
	}
	if (
			!(msg->mesl_curpl_encrypted)
	) {
		// CASE OF: MAVLink frame should be encrypted (iflag), but isn't.
		//          This may be the case for decrypted MAVLink frame.
		mesl_edit_mav_encrypt(
				(mavlink_status_t*)0,
				msg->msgid,
				len_p,
				msg->sysid,
				msg->compid,
				incompat_flags_p,
				_MAV_PAYLOAD(msg),
				payload_dst
				);
		if ((*incompat_flags_p) & MAVLINK_IFLAG_MESL_CRYPTO_METHOD) {
			*payload_result_addr = payload_dst;
		}
		else {
			*payload_result_addr = _MAV_PAYLOAD(msg);
		}
	}
}

MAVLINK_HELPER void mesl_edit_mav_decrypt(
		mavlink_status_t* status,
		mavlink_message_t* rxmsg
) {
	int32_t decrypted_len = 0;
	uint8_t mesl_crypto_method;
	// Set this flag early, before decryption.
	rxmsg->mesl_curpl_encrypted = (uint8_t)0;
	// ;
	if (status->msg_received == MAVLINK_FRAMING_OK) {
		// CASE OF: Parsing include CRC and signature ended, successfully,
		//            but not decryption.
		mesl_crypto_method = (rxmsg->incompat_flags &
				MAVLINK_IFLAG_MESL_CRYPTO_METHOD);
		mesl_crypto_method = mesl_crypto_method >> BITSHIFT_MESL_CRYPTO_METHOD;
		if (mesl_crypto_method) {
			// CASE OF: Payload encrypted MAVLink frame.
			status->mesl_crypto_method_rx = mesl_crypto_method;
			memcpy(
					(char*)status->mesl_crypto_buf,
					_MAV_PAYLOAD(rxmsg),
					rxmsg->len);
			decrypted_len = mavlink_mesl_decrypt(
					mesl_crypto_method,
					(const char*)status->mesl_crypto_buf,
					(char *)(_MAV_PAYLOAD_NON_CONST(rxmsg)),
					rxmsg->len,
					MAVLINK_MAX_PAYLOAD_LEN
					);
			if (decrypted_len < (int32_t)0 ||
					decrypted_len > (int32_t)MAVLINK_MAX_PAYLOAD_LEN) {
				// CASE OF: error when doing decryption,
				//            includes case for 'rxmsg->len == 0'.
				rxmsg->len = (uint8_t)0;
				rxmsg->mesl_curpl_encrypted = (uint8_t)1;
				_mav_parse_error(status);
				status->parse_state = MAVLINK_PARSE_STATE_IDLE;
			}
			else {
				// NOTE: decryption with non-zero len to zero len, can be valid.
				rxmsg->len = (uint8_t)decrypted_len;
			}
		}
		else if (rxmsg->len != (uint8_t)0) {
			status->mesl_crypto_method_rx = mesl_crypto_method;
		}
	}
}

#endif // #ifdef MESL_CRYPTO



#ifdef MAVLINK_USE_CXX_NAMESPACE
} // namespace mavlink
#endif

//EOF
