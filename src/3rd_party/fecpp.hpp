/*
 * Forward error correction based on Vandermonde matrices
 *
 * (C) 1997-1998 Luigi Rizzo (luigi@iet.unipi.it)
 * (C) 2009 Jack Lloyd (jack@randombit.net)
 *
 * Distributed under the terms given in license.txt
 *
 * Modified by cnbatch
 * November 2023
 */

#ifndef FECPP_HPP_
#define FECPP_HPP_

#include <map>
#include <vector>
#include <functional>
#include <cstdint>
#include <memory>

namespace fecpp
{
	using std::uint8_t;
	using std::size_t;

	using byte = std::uint8_t;

#if defined(__i386__)|| defined(__amd64__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64) || defined(_M_AMD64)
#define FECPP_IS_X86
#endif

	/**
	* Forward error correction code
	*/
	class fec_code
	{
	public:
		fec_code() : K(0), N(0) {};

		/**
		* fec_code constructor
		* @param K the number of shares needed for recovery
		* @param N the number of shares generated
		*/
		fec_code(size_t K, size_t n);
		
		/**
		* fec_code initialiser
		* @param K the number of shares needed for recovery
		* @param N the number of shares generated
		*/
		void reset_martix(size_t K, size_t n);

		size_t get_K() const { return K; }
		size_t get_N() const { return N; }

		/**
		* @param input the data to FEC
		* @param data_length the length in bytes of input's uint8_t[]
		* @param block_size the length in bytes of each block
		* @return redundant data
		*/
		std::vector<std::unique_ptr<uint8_t[]>> encode(const uint8_t input[], size_t data_length, size_t block_size) const;

		/**
		* @param shares map of share id to share contents
		* @param share_size size in bytes of each share
		* @return missed data with sequence number
		*/
		std::map<size_t, std::vector<uint8_t>> decode(const std::map<size_t, const uint8_t*> &shares, size_t share_size) const;

	private:
		size_t K, N;
		std::vector<uint8_t> enc_matrix;

		/**
		* matrix initialiser
		*/
		void setup_matrix();
	};

#if defined(FECPP_IS_X86)
	size_t addmul_ssse3(uint8_t z[], const uint8_t x[], uint8_t y, size_t size);
#endif

}

#endif
