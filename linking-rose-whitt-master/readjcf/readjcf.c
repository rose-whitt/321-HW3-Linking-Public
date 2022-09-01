/*
 * COMP 321 Project 3: Linking
 * 
 * This program reads a single Java Class File and prints out its
 * dependencies and exports, as requested by command-line flags.
 * 
 * Rose Whitt & Madison Roy; rew9 & mmr11
 */

#include <netinet/in.h>

#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "csapp.h"

// Define the magic number that must be the first four bytes of a valid JCF.
#define JCF_MAGIC 0xCAFEBABE

/* 
 * Define the header of the Java class file.
 * The __attribute__((packed)) after the structure definition tells the
 * compiler to not add any padding to the structure for alignment.  This
 * allows this structure to be read directly from a packed file.
 */
struct jcf_header
{
	uint32_t magic;
	uint16_t minor_version;
	uint16_t major_version;
} __attribute__((packed));

// Define the body of the Java class file.
struct jcf_body
{
	uint16_t access_flags;
	uint16_t this_class;
	uint16_t super_class;
} __attribute__((packed));

// Define an enumeration of the constant tags.
enum jcf_cp_tags
{
	JCF_CONSTANT_Class = 7,
	JCF_CONSTANT_Fieldref = 9,
	JCF_CONSTANT_Methodref = 10,
	JCF_CONSTANT_InterfaceMethodref = 11,
	JCF_CONSTANT_String = 8,
	JCF_CONSTANT_Integer = 3,
	JCF_CONSTANT_Float = 4,
	JCF_CONSTANT_Long = 5,
	JCF_CONSTANT_Double = 6,
	JCF_CONSTANT_NameAndType = 12,
	JCF_CONSTANT_Utf8 = 1,
	JCF_CONSTANT_MethodHandle = 15,
	JCF_CONSTANT_MethodType = 16,
	JCF_CONSTANT_InvokeDynamic = 18
};

// Define an enumeration of the access flags.
enum jcf_access_flags
{
	JCF_ACC_PUBLIC = 0x0001,
	JCF_ACC_PRIVATE = 0x0002,
	JCF_ACC_PROTECTED = 0x0004,
	JCF_ACC_STATIC = 0x0008,
	JCF_ACC_FINAL = 0x0010,
	JCF_ACC_SYNCHRONIZED = 0x0020,
	JCF_ACC_VOLATILE = 0x0040,
	JCF_ACC_TRANSIENT = 0x0080,
	JCF_ACC_NATIVE = 0x0100,
	JCF_ACC_INTERFACE = 0x0200,
	JCF_ACC_ABSTRACT = 0x0400,
	JCF_ACC_STRICT = 0x0800
};

/*
 * Define the generic constant pool info structure.
 * This structure should be thought of as an abstract class that never
 * should be allocated directly. 
 *
 * The zero length array "info" in this structure is a special design
 * pattern in C that allows for variable length structures.  This is
 * done by casting another structure to this general type or by
 * allocating (sizeof(struct foo) + array_len) bytes.  This causes
 * memory to be allocated for the array, which can then be accessed
 * normally.
 */
struct jcf_cp_info
{
	uint8_t tag;
	uint8_t info[0];
} __attribute__((packed));

/* 
 * Define the generic constant pool info structure for all constants
 * that have a single u2.
 */
struct jcf_cp_info_1u2
{
	uint8_t tag;
	uint16_t u2;
} __attribute__((packed));

/* 
 * Define the generic constant pool info structure for all constants
 * that have two u2s.
 */
struct jcf_cp_info_2u2
{
	uint8_t tag;
	struct
	{
		uint16_t u2_1;
		uint16_t u2_2;
	} __attribute__((packed)) body;
} __attribute__((packed));

/* 
 * Define the generic constant pool info structure for all constants
 * that have two u4s.
 */
struct jcf_cp_info_2u4
{
	uint8_t tag;
	struct
	{
		uint32_t u4_1;
		uint32_t u4_2;
	} __attribute__((packed)) body;
} __attribute__((packed));

/* 
 * Define the generic constant pool info structure for all constants
 * that have one u1 and one u2.
 */
struct jcf_cp_info_1u1_1u2
{
	uint8_t tag;
	struct
	{
		uint8_t u1;
		uint16_t u2;
	} __attribute__((packed)) body;
} __attribute__((packed));

/* 
 * Define the generic constant pool info structure for all constants
 * that have a single u4.
 */
struct jcf_cp_info_1u4
{
	uint8_t tag;
	uint32_t u4;
} __attribute__((packed));

// Define the constant pool info for classes.
struct jcf_cp_class_info
{
	uint8_t tag;
	uint16_t name_index;
} __attribute__((packed));

/*
 * Define the constant pool info for all reference constants.
 * These are any of the following constants: JCF_CONSTANT_Fieldref,
 * JCF_CONSTANT_Methodref, and JCF_CONSTANT_InterfaceMethodref.
 */
struct jcf_cp_ref_info
{
	uint8_t tag;
	uint16_t class_index;
	uint16_t name_and_type_index;
} __attribute__((packed));

// Define the constant pool info for name and type tuples.
struct jcf_cp_nameandtype_info
{
	uint8_t tag;
	uint16_t name_index;
	uint16_t descriptor_index;
} __attribute__((packed));

/*
 * Define the constant pool info for UTF8 strings.
 * 
 * This structure should be created by allocating
 * (sizeof(struct jcf_cp_utf8_info) + array_len) bytes.
 */
struct jcf_cp_utf8_info
{
	uint8_t tag;
	uint16_t length;
	uint8_t bytes[0];
} __attribute__((packed));

// Define a field info entry for the class.
struct jcf_field_info
{
	uint16_t access_flags;
	uint16_t name_index;
	uint16_t descriptor_index;
} __attribute__((packed));

// Define a method info entry for the class.
struct jcf_method_info
{
	uint16_t access_flags;
	uint16_t name_index;
	uint16_t descriptor_index;
} __attribute__((packed));

// Define a structure for holding the constant pool.
struct jcf_constant_pool
{
	uint16_t count;
	struct jcf_cp_info **pool;
};

// Define a structure for holding processing state.
struct jcf_state
{
	FILE *f;
	bool depends_flag;
	bool exports_flag;
	bool verbose_flag;
	struct jcf_constant_pool constant_pool;
};

// Declare the local function prototypes.
static void readjcf_error(void);
static int print_jcf_constant(struct jcf_state *jcf,
							  uint16_t index, uint8_t expected_tag);
static int process_jcf_header(struct jcf_state *jcf);
static int process_jcf_constant_pool(struct jcf_state *jcf);
static void destroy_jcf_constant_pool(struct jcf_constant_pool *pool);
static int process_jcf_body(struct jcf_state *jcf);
static int process_jcf_interfaces(struct jcf_state *jcf);
static int process_jcf_fields(struct jcf_state *jcf);
static int process_jcf_methods(struct jcf_state *jcf);
static int process_jcf_fields_and_methods_helper(struct jcf_state *jcf);
static int process_jcf_attributes(struct jcf_state *jcf);

/*
 * Requires:
 *   Nothing.
 *
 * Effects:
 *   Prints a formatted error message to stderr.
 */
static void
readjcf_error(void)
{

	fprintf(stderr, "ERROR: Unable to process file!\n");
}

/*
 * Requires:
 *   The constant pool must be initialized.
 *
 * Effects:
 *   If the index is valid and points to a constant of the expected type,
 *   this function will print the constant and return 0.  Otherwise, -1
 *   is returned.
 */
static int
print_jcf_constant(struct jcf_state *jcf, uint16_t index,
				   uint8_t expected_tag)
{
	struct jcf_cp_info *info;

	assert(jcf != NULL);

	// Verify the index is valid. (index not zero, index < count)
	if (index == 0 || index >= jcf->constant_pool.count)
	{
		return (-1);
	}

	// Verify the tag. (expected tag is same as tag at index)
	info = jcf->constant_pool.pool[index];
	if (expected_tag != info->tag)
	{
		return (-1);
	}

	// Print the constant.
	switch (info->tag)
	{
	case JCF_CONSTANT_Class:
	{
		// Print the class.
		struct jcf_cp_class_info *class = (struct jcf_cp_class_info *)info;
		print_jcf_constant(jcf, class->name_index, JCF_CONSTANT_Utf8);
		break;
	}
	case JCF_CONSTANT_Fieldref:
	case JCF_CONSTANT_Methodref:
	case JCF_CONSTANT_InterfaceMethodref:
	{
		/* 
		 * Print the reference, with the Class and NameAndType
		 * separated by a '.'.
		 */
		struct jcf_cp_ref_info *ref = (struct jcf_cp_ref_info *)info;
		print_jcf_constant(jcf, ref->class_index, JCF_CONSTANT_Class);
		printf(".");
		print_jcf_constant(jcf, ref->name_and_type_index,
						   JCF_CONSTANT_NameAndType);
		break;
	}
	case JCF_CONSTANT_NameAndType:
	{
		// Print the name and type.
		struct jcf_cp_nameandtype_info *name_and_type =
			(struct jcf_cp_nameandtype_info *)info;
		print_jcf_constant(jcf, name_and_type->name_index, JCF_CONSTANT_Utf8);
		printf(" ");
		print_jcf_constant(jcf, name_and_type->descriptor_index,
						   JCF_CONSTANT_Utf8);
		break;
	}
	case JCF_CONSTANT_Utf8:
	{
		// Print the UTF8.
		struct jcf_cp_utf8_info *utf8 = (struct jcf_cp_utf8_info *)info;
		printf("%.*s", utf8->length, utf8->bytes);
		break;
	}
	default:
		// Ignore all other constants.
		break;
	}

	return (0);
}

/*
 * Requires:
 *   The "jcf" argument must be a valid struct jcf_state.  "jcf.f" must
 *   be a valid open file.
 *
 * Effects:
 *   Reads and verifies the Java class file header from file "jcf.f".
 *   Returns 0 on success and -1 on failure.
 */
static int
process_jcf_header(struct jcf_state *jcf)
{

	struct jcf_header header;

	assert(jcf != NULL);

	// Read the header.
	if (fread(&header, sizeof(struct jcf_header), 1, jcf->f) != 1)
	{
		return (-1);
	}

	//Byteswapping
	header.magic = ntohl(header.magic);
	header.minor_version = ntohs(header.minor_version);
	header.major_version = ntohs(header.major_version);

	// Verify the magic number.
	if (header.magic != JCF_MAGIC)
	{
		return (-1);
	}

	return (0);
}

/*
 * Requires:
 *   The "jcf" argument must be a valid struct jcf_state.  "jcf.f" must
 *   be a valid open file.  The JCF header must have already been read.
 *
 * Effects:
 *   Reads and stores the constant pool from the JCF.  Prints the
 *   dependencies if requested.  Returns 0 on success and -1 on failure.
 *   This function allocates memory that must be destroyed later, even if
 *   the function fails.
 */
static int
process_jcf_constant_pool(struct jcf_state *jcf)
{
	int i;
	uint16_t constant_pool_count;
	uint8_t tag;

	assert(jcf != NULL);
	assert(jcf->constant_pool.pool == NULL);

	// Read the constant pool count.
	if (fread(&constant_pool_count,
			  sizeof(constant_pool_count), 1, jcf->f) != 1)
	{
		return (-1);
	}
	constant_pool_count = ntohs(constant_pool_count);

	// Mallocate the constant pool.
	struct jcf_cp_info **constant_pool_arr;
	constant_pool_arr = malloc(constant_pool_count *
							   sizeof(struct jcf_cp_info *));

	// Assign jcf pool struct pointers
	jcf->constant_pool.pool = constant_pool_arr;
	jcf->constant_pool.count = constant_pool_count;

	// Read the constant pool.
	for (i = 1; i < constant_pool_count; i++)
	{
		// read the tag
		if (fread(&tag, sizeof(tag), 1, jcf->f) != 1)
		{
			return (-1);
		}

		// testing
		if (jcf->verbose_flag)
		{
			printf("Tag #%u: %u\n", i, tag);
		}

		// Process the rest of the constant info.
		switch (tag)
		{
		case JCF_CONSTANT_String:	  // u1 (uint8_t), u2 (uint16_t)
		case JCF_CONSTANT_Class:	  // u1, u2
		case JCF_CONSTANT_MethodType: // u1, u2
		{
			// testing
			if (jcf->verbose_flag)
			{
				printf("Case: Method\n");
			}

			// make a 16
			uint16_t u2_val;

			// read index
			if (fread(&u2_val, sizeof(uint16_t), 1, jcf->f) != 1)
			{
				return (-1);
			}

			// byte swap
			u2_val = ntohs(u2_val);

			/**
			 * make pointer of the current struct type 
			 * with size of current struct type
			 */
			struct jcf_cp_info_1u2 *ptr =
				malloc(sizeof(struct jcf_cp_info_1u2));

			// accesses the ith, cast ptr this struct
			*(constant_pool_arr + i) = (struct jcf_cp_info *)ptr;

			// updates values
			ptr->tag = tag;
			ptr->u2 = u2_val;

			// testing
			if (jcf->verbose_flag)
			{
				printf("end of method\n");
				printf("-\n");
			}

			break;
		}
		case JCF_CONSTANT_Fieldref:
		case JCF_CONSTANT_Methodref:
		case JCF_CONSTANT_InterfaceMethodref:
		case JCF_CONSTANT_NameAndType:
		case JCF_CONSTANT_InvokeDynamic:
		{
			// testing
			if (jcf->verbose_flag)
			{
				printf("Case: Invoke\n");
			}

			// make a 16
			uint16_t u2_val1;
			// read index
			if (fread(&u2_val1, sizeof(uint16_t), 1, jcf->f) != 1)
			{
				return (-1);
			}
			// ntohs idx byte swap
			u2_val1 = ntohs(u2_val1);

			// make a 16
			uint16_t u2_val2;

			// read index
			if (fread(&u2_val2, sizeof(uint16_t), 1, jcf->f) != 1)
			{
				return (-1);
			}

			// ntohs idx byte swap
			u2_val2 = ntohs(u2_val2);

			/**
			 * make pointer of the current struct type
			 * with size of current struct type (*ptr name)
			 */
			struct jcf_cp_info_2u2 *ptr =
				malloc(sizeof(struct jcf_cp_info_2u2));

			// accesses the ith, cast ptr this struct
			*(constant_pool_arr + i) = (struct jcf_cp_info *)ptr;

			// update values
			ptr->tag = tag;
			ptr->body.u2_1 = u2_val1;
			ptr->body.u2_2 = u2_val2;

			// testing
			if (jcf->verbose_flag)
			{
				printf("end of invoke\n");
				printf("-\n");
			}

			break;
		}
		case JCF_CONSTANT_Integer:
		case JCF_CONSTANT_Float:
		{
			// testing
			if (jcf->verbose_flag)
			{
				printf("Case: Float\n");
			}

			// make a 32
			uint32_t u4_val;
			// read index
			if (fread(&u4_val, sizeof(uint32_t), 1, jcf->f) != 1)
			{
				return (-1);
			}
			// ntohs idx byte swap
			u4_val = ntohs(u4_val);

			/**
			 * make pointer of the current struct type
			 * with size of current struct type
			 */
			struct jcf_cp_info_1u4 *ptr =
				malloc(sizeof(struct jcf_cp_info_1u4));

			// accesses the ith, cast ptr this struct
			*(constant_pool_arr + i) = (struct jcf_cp_info *)ptr;

			// update values
			ptr->tag = tag;
			ptr->u4 = u4_val;

			// testing
			if (jcf->verbose_flag)
			{
				printf("end of float\n");
				printf("-\n");
			}

			break;
		}
		case JCF_CONSTANT_Long:
		case JCF_CONSTANT_Double:
		{
			// testing
			if (jcf->verbose_flag)
			{
				printf("Case: Double\n");
			}

			/**
			 * make pointer of the current struct type
			 * with size of current struct type
			 * using the structure for 2 u4s that we made
			 */
			struct jcf_cp_info_2u4 *ptr =
				malloc(sizeof(struct jcf_cp_info_2u4 *));

			// read first u4
			if (fread(&ptr->body.u4_1,
					  sizeof(ptr->body.u4_1), 1, jcf->f) != 1)
			{
				return (-1);
			}

			// read second u4
			if (fread(&ptr->body.u4_2, sizeof(ptr->body.u4_2),
					  1, jcf->f) != 1)
			{
				return (-1);
			}

			// update values
			ptr->tag = tag;
			ptr->body.u4_1 = ntohl(ptr->body.u4_1);
			ptr->body.u4_2 = ntohl(ptr->body.u4_2);

			// long and double take up two indices, increment i
			i++;

			// testing
			if (jcf->verbose_flag)
			{
				printf("end of double\n");
				printf("-");
			}

			break;
		}
		case JCF_CONSTANT_Utf8: // u1, u2, u1
		{
			// testing
			if (jcf->verbose_flag)
			{
				printf("Case: Utf8\n");
			}

			// make length to read to
			uint16_t length;

			// read index
			if (fread(&length, sizeof(uint16_t), 1, jcf->f) != 1)
			{
				return (-1);
			}

			// byte swap
			length = ntohs(length);

			/**
			 * make pointer of the current struct type
			 * with size of current struct type
			 */
			struct jcf_cp_utf8_info *ptr =
				malloc((sizeof(struct jcf_cp_utf8_info) + length + 1));

			// accesses the ith, cast ptr this struct
			*(constant_pool_arr + i) = (struct jcf_cp_info *)ptr;

			// update values
			ptr->tag = tag;
			ptr->length = length;

			// nul-terminate
			ptr->bytes[length] = '\0';

			// read to bytes
			fread(&ptr->bytes, sizeof(uint8_t), length, jcf->f);

			// testing
			if (jcf->verbose_flag)
			{
				printf("end of utf8\n");
				printf("-\n");
			}

			break;
		}
		case JCF_CONSTANT_MethodHandle:
		{
			// testing
			if (jcf->verbose_flag)
			{
				printf("Case: Method\n");
			}

			uint8_t u1_val;

			// read index
			if (fread(&u1_val, sizeof(uint8_t), 1, jcf->f) != 1)
			{
				return (-1);
			}

			uint16_t u2_val;
			// read index
			if (fread(&u2_val, sizeof(uint16_t), 1, jcf->f) != 1)
			{
				return (-1);
			}
			// ntohs idx byte swap
			u2_val = ntohs(u2_val);

			/**
			 * make pointer of the current struct type 
			 * with size of current struct type
			 */
			struct jcf_cp_info_1u1_1u2 *ptr =
				malloc(sizeof(struct jcf_cp_info_1u1_1u2));

			// accesses the ith, cast ptr this struct
			*(constant_pool_arr + i) = (struct jcf_cp_info *)ptr;

			// update values
			ptr->tag = tag;
			ptr->body.u1 = u1_val;
			ptr->body.u2 = u2_val;

			// testing
			if (jcf->verbose_flag)
			{
				printf("end of method\n");
				printf("-");
			}

			break;
		}
		default:
			return (-1);
		}
	}

	/* 
	 * Print the dependencies if requested.  This must be done after
	 * reading the entire pool because there are no guarantees about
	 * constants not containing references to other constants after
	 * them in the pool. 
	 */

	if (jcf->depends_flag)
	{
		for (i = 1; i < constant_pool_count; i++)
		{

			if (jcf->constant_pool.pool[i] != NULL)
			{
				if (jcf->constant_pool.pool[i]->tag == JCF_CONSTANT_Fieldref)
				{
					printf("Dependency - ");
					print_jcf_constant(jcf, i, JCF_CONSTANT_Fieldref);
					printf("\n");
				}
				else if (jcf->constant_pool.pool[i]->tag == JCF_CONSTANT_Methodref)
				{
					printf("Dependency - ");
					print_jcf_constant(jcf, i, JCF_CONSTANT_Methodref);
					printf("\n");
				}
				else if (jcf->constant_pool.pool[i]->tag == JCF_CONSTANT_InterfaceMethodref)
				{
					printf("Dependency - ");
					print_jcf_constant(jcf, i,
									   JCF_CONSTANT_InterfaceMethodref);
					printf("\n");
				}
			}
		}
	}

	return (0);
}

/*
 * Requires:
 *   The "pool" argument must be a valid JCF constant pool.
 *
 * Effects:
 *   Frees the memory allocated to store the constant pool.
 */
static void
destroy_jcf_constant_pool(struct jcf_constant_pool *pool)
{

	assert(pool != NULL);
	assert(pool->pool != NULL);
	int index;

	// Free each element in the pool if it is occupied
	for (index = 1; index < pool->count; index++)
	{
		if (pool->pool[index] != NULL)
		{
			free(pool->pool[index]);
		}
	}

	// Free the entire pool itself
	free(pool->pool);
}

/*
 * Requires:
 *   The "jcf" argument must be a valid struct jcf_state.  "jcf.f" must
 *   be a valid open file.  The JCF header and constant pool must have
 *   already been read.
 *
 * Effects:
 *   Reads the Java class file body from file "jcf.f".  Returns 0 on
 *   success.
 */
static int
process_jcf_body(struct jcf_state *jcf)
{

	struct jcf_body body;

	assert(jcf != NULL);

	// Read the body. - access_flags, this_class, and super_class
	if (fread(&body, sizeof(struct jcf_body), 1, jcf->f) != 1)
	{
		return (-1);
	}

	return (0);
}

// TO DO!!!!!!!!!! 🏳️‍🌈🏳️‍🌈🏳️‍🌈🏳️‍🌈🏳️‍🌈🏳️‍🌈🏳️‍🌈
/*
 * Requires:
 *   The "jcf" argument must be a valid struct jcf_state.  "jcf.f" must
 *   be a valid open file.  The JCF header, constant pool, and body must
 *   have already been read.
 *
 * Effects:
 *   Reads the Java class file interfaces from file "jcf.f".  Returns
 *   0 on success.
 */
static int
process_jcf_interfaces(struct jcf_state *jcf)
{
	int index;
	uint16_t count;
	uint16_t interface;

	count = ntohs(count);
	interface = ntohs(interface);

	assert(jcf != NULL);

	// Read the interfaces count.
	if (fread(&count, sizeof(count), 1, jcf->f) != 1)
	{
		return (-1);
	}
	count = ntohs(count);

	// Read the interfaces.
	for (index = 0; index < count; index++)
	{
		if (fread(&interface, sizeof(interface), 1, jcf->f) != 1)
		{
			return (-1);
		}
	}

	return (0);
}

/*
 * Requires:
 *   The "jcf" argument must be a valid struct jcf_state.  "jcf.f" must
 *   be a valid open file.  The JCF header, constant pool, body, and
 *   interfaces must have already been read.  The JCF constant pool in
 *   "jcf" must be initialized.
 *
 * Effects:
 *   Reads the Java class file fields from file "jcf.f".  Prints the
 *   exported fields, if requested.  Returns 0 on success and -1 on
 *   failure.
 */
static int
process_jcf_fields(struct jcf_state *jcf)
{
	return (process_jcf_fields_and_methods_helper(jcf));
}

/*
 * Requires:
 *   The "jcf" argument must be a valid struct jcf_state.  "jcf.f" must
 *   be a valid open file.  The JCF header, constant pool, body,
 *   interfaces, and fields must have already been read.  The JCF
 *   constant pool in "jcf" must be initialized.
 *
 * Effects:
 *   Reads the Java class file methods from file "jcf.f".  Prints the
 *   exported methods, if requested.  Returns 0 on success and -1 on
 *   failure.
 */
static int
process_jcf_methods(struct jcf_state *jcf)
{

	return (process_jcf_fields_and_methods_helper(jcf));
}

/*
 * Requires:
 *   All the requirements of either process_jcf_fields or
 *   process_jcf_methods.
 *
 * Effects:
 *   Reads the Java class file fields or methods from file "jcf.f".
 *   Prints the exports, if requested.  Returns 0 on success and -1 on
 *   failure.
 */
static int
process_jcf_fields_and_methods_helper(struct jcf_state *jcf)
{
	int i;
	struct jcf_field_info info;
	uint16_t count;

	assert(jcf != NULL);

	// Read the count.
	if (fread(&count, sizeof(count), 1, jcf->f) != 1)
		return (-1);
	count = ntohs(count);

	// Read the methods.
	for (i = 0; i < count; i++)
	{
		// Read the info.
		if (fread(&info, sizeof(info), 1, jcf->f) != 1)
			return (-1);
		info.access_flags = ntohs(info.access_flags);
		info.name_index = ntohs(info.name_index);
		info.descriptor_index = ntohs(info.descriptor_index);

		// Print the info.
		if (jcf->exports_flag &&
			info.access_flags & JCF_ACC_PUBLIC)
		{
			printf("Export - ");
			if (print_jcf_constant(jcf, info.name_index,
								   JCF_CONSTANT_Utf8) != 0)
				return (-1);
			printf(" ");
			if (print_jcf_constant(jcf, info.descriptor_index,
								   JCF_CONSTANT_Utf8) != 0)
				return (-1);
			printf("\n");
		}

		// Read the attributes.
		if (process_jcf_attributes(jcf) != 0)
			return (-1);
	}

	return (0);
}

/*
 * Requires:
 *   The "jcf" argument must be a valid struct jcf_state.  "jcf.f" must
 *   be a valid open file.  The next part of the JCF to be read must be
 *   an attributes count, followed by an array of attributes exactly
 *   count long.
 *
 * Effects:
 *   Reads the attributes.  Returns 0 on success and -1 on failure.
 */
static int
process_jcf_attributes(struct jcf_state *jcf)
{
	int i;
	uint16_t attributes_count;

	assert(jcf != NULL);

	// Read the attributes count.
	if (fread(&attributes_count, sizeof(attributes_count), 1, jcf->f) != 1)
	{
		return (-1);
	}
	attributes_count = ntohs(attributes_count);

	// Read the attributes.
	for (i = 0; i < attributes_count; i++)
	{
		uint16_t name_index;
		uint32_t length;
		uint8_t info_data;
		uint32_t j;

		// Read the attribute name index.
		if (fread(&name_index, sizeof(name_index), 1, jcf->f) != 1)
		{
			return (-1);
		}
		name_index = ntohs(name_index);

		// Read the attribute length.
		if (fread(&length, sizeof(length), 1, jcf->f) != 1)
		{
			return (-1);
		}
		length = ntohl(length);

		// Read the attribute data.
		for (j = 0; j < length; j++)
		{
			if (fread(&info_data, sizeof(info_data), 1, jcf->f) != 1)
			{
				return (-1);
			}
		}

		// testing
		if (jcf->verbose_flag)
		{
			printf("Attributes count: %u\n", attributes_count);
			printf("	Attribute #0: name index: %u\n", name_index);
			printf("	Attribute #0: length: %u\n", length);
		}
	}

	return (0);
}

/* 
 * Requires:
 *   Nothing.
 *
 * Effects:
 *   Reads the Java class file and performs pass 1 verification.  Also
 *   prints the class' dependencies and exports, if requested.
 */
int main(int argc, char **argv)
{

	// Define the structure for holding all of the processing state.
	struct jcf_state jcf;

	int c; // Option character

	// Error return: Was there an error during processing?
	int err;

	extern int optind; // Option index

	// Abort flag: Was there an error on the command line?
	bool abort_flag = false;

	// Option flags: Were these options on the command line?
	bool depends_flag = false;
	bool exports_flag = false;
	bool verbose_flag = false;

	//printf("processing command line args\n");

	// Process the command line arguments.
	while ((c = getopt(argc, argv, "dev")) != -1)
	{
		switch (c)
		{
		case 'd':
			// Print depends.
			if (depends_flag)
			{
				// A flag can only appear once.
				abort_flag = true;
			}
			else
			{
				depends_flag = true;
			}
			break;
		case 'e':
			// Print exports.
			if (exports_flag)
			{
				// A flag can only appear once.
				abort_flag = true;
			}
			else
			{
				exports_flag = true;
			}
			break;
		case 'v':
			// Be verbose.
			if (verbose_flag)
			{
				// A flag can only appear once.
				abort_flag = true;
			}
			else
			{
				verbose_flag = true;
			}
			break;
		case '?':
			// An error character was returned by getopt().
			abort_flag = true;
		}
	}

	if (abort_flag || optind == argc || argc > optind + 1)
	{
		fprintf(stderr, "usage: %s [-d] [-e] [-v] <input filename>\n",
				argv[0]);
		return (1); // Indicate an error.
	}

	// Initialize the jcf_state structure.
	jcf.f = NULL;
	jcf.depends_flag = depends_flag;
	jcf.exports_flag = exports_flag;
	jcf.verbose_flag = verbose_flag;
	jcf.constant_pool.count = 0;
	jcf.constant_pool.pool = NULL;

	// Open the class file.
	jcf.f = fopen(argv[optind], "r");
	if (jcf.f == NULL)
	{
		readjcf_error();
		return (1); // Indicate an error.
	}

	// Process the JCF header.
	err = process_jcf_header(&jcf);
	if (err != 0)
		goto failed;

	// Process the JCF constant pool.
	err = process_jcf_constant_pool(&jcf);
	if (err != 0)
	{
		// testing
		if (jcf.verbose_flag)
		{
			printf("Process Constant Pool Failed!\n");
		}
		goto failed;
	}

	// Process the JCF body.
	err = process_jcf_body(&jcf);
	if (err != 0)
		goto failed;

	// Process the JCF interfaces.
	err = process_jcf_interfaces(&jcf);
	if (err != 0)
		goto failed;

	// Process the JCF fields.
	err = process_jcf_fields(&jcf);
	if (err != 0)
		goto failed;

	// Process the JCF methods.
	err = process_jcf_methods(&jcf);
	if (err != 0)
		goto failed;

	// Process the JCF final attributes.
	err = process_jcf_attributes(&jcf);
	if (err != 0)
		goto failed;

	// Check for extra data.
	if (fgetc(jcf.f) != EOF)
	{
		err = -1;
		goto failed;
	}

failed:
	if (jcf.constant_pool.pool != NULL)
		destroy_jcf_constant_pool(&jcf.constant_pool);
	fclose(jcf.f);
	if (err != 0)
	{
		readjcf_error();
		return (1); // Indicate an error.
	}
	return (0);
}