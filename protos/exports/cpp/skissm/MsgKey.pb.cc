// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: skissm/MsgKey.proto

#include "skissm/MsgKey.pb.h"

#include <algorithm>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/wire_format_lite.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>

PROTOBUF_PRAGMA_INIT_SEG
namespace skissm {
constexpr MsgKey::MsgKey(
  ::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized)
  : derived_key_(&::PROTOBUF_NAMESPACE_ID::internal::fixed_address_empty_string)
  , index_(0u){}
struct MsgKeyDefaultTypeInternal {
  constexpr MsgKeyDefaultTypeInternal()
    : _instance(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized{}) {}
  ~MsgKeyDefaultTypeInternal() {}
  union {
    MsgKey _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT MsgKeyDefaultTypeInternal _MsgKey_default_instance_;
}  // namespace skissm
static ::PROTOBUF_NAMESPACE_ID::Metadata file_level_metadata_skissm_2fMsgKey_2eproto[1];
static constexpr ::PROTOBUF_NAMESPACE_ID::EnumDescriptor const** file_level_enum_descriptors_skissm_2fMsgKey_2eproto = nullptr;
static constexpr ::PROTOBUF_NAMESPACE_ID::ServiceDescriptor const** file_level_service_descriptors_skissm_2fMsgKey_2eproto = nullptr;

const uint32_t TableStruct_skissm_2fMsgKey_2eproto::offsets[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::skissm::MsgKey, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  ~0u,  // no _inlined_string_donated_
  PROTOBUF_FIELD_OFFSET(::skissm::MsgKey, index_),
  PROTOBUF_FIELD_OFFSET(::skissm::MsgKey, derived_key_),
};
static const ::PROTOBUF_NAMESPACE_ID::internal::MigrationSchema schemas[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  { 0, -1, -1, sizeof(::skissm::MsgKey)},
};

static ::PROTOBUF_NAMESPACE_ID::Message const * const file_default_instances[] = {
  reinterpret_cast<const ::PROTOBUF_NAMESPACE_ID::Message*>(&::skissm::_MsgKey_default_instance_),
};

const char descriptor_table_protodef_skissm_2fMsgKey_2eproto[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) =
  "\n\023skissm/MsgKey.proto\022\006skissm\",\n\006MsgKey\022"
  "\r\n\005index\030\001 \001(\r\022\023\n\013derived_key\030\002 \001(\014B\'\n\030o"
  "rg.e2eelab.skissm.protoB\013MsgKeyProtob\006pr"
  "oto3"
  ;
static ::PROTOBUF_NAMESPACE_ID::internal::once_flag descriptor_table_skissm_2fMsgKey_2eproto_once;
const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_skissm_2fMsgKey_2eproto = {
  false, false, 124, descriptor_table_protodef_skissm_2fMsgKey_2eproto, "skissm/MsgKey.proto", 
  &descriptor_table_skissm_2fMsgKey_2eproto_once, nullptr, 0, 1,
  schemas, file_default_instances, TableStruct_skissm_2fMsgKey_2eproto::offsets,
  file_level_metadata_skissm_2fMsgKey_2eproto, file_level_enum_descriptors_skissm_2fMsgKey_2eproto, file_level_service_descriptors_skissm_2fMsgKey_2eproto,
};
PROTOBUF_ATTRIBUTE_WEAK const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable* descriptor_table_skissm_2fMsgKey_2eproto_getter() {
  return &descriptor_table_skissm_2fMsgKey_2eproto;
}

// Force running AddDescriptors() at dynamic initialization time.
PROTOBUF_ATTRIBUTE_INIT_PRIORITY static ::PROTOBUF_NAMESPACE_ID::internal::AddDescriptorsRunner dynamic_init_dummy_skissm_2fMsgKey_2eproto(&descriptor_table_skissm_2fMsgKey_2eproto);
namespace skissm {

// ===================================================================

class MsgKey::_Internal {
 public:
};

MsgKey::MsgKey(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena, is_message_owned) {
  SharedCtor();
  if (!is_message_owned) {
    RegisterArenaDtor(arena);
  }
  // @@protoc_insertion_point(arena_constructor:skissm.MsgKey)
}
MsgKey::MsgKey(const MsgKey& from)
  : ::PROTOBUF_NAMESPACE_ID::Message() {
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  derived_key_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    derived_key_.Set(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), "", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (!from._internal_derived_key().empty()) {
    derived_key_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, from._internal_derived_key(), 
      GetArenaForAllocation());
  }
  index_ = from.index_;
  // @@protoc_insertion_point(copy_constructor:skissm.MsgKey)
}

inline void MsgKey::SharedCtor() {
derived_key_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
#ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
  derived_key_.Set(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), "", GetArenaForAllocation());
#endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
index_ = 0u;
}

MsgKey::~MsgKey() {
  // @@protoc_insertion_point(destructor:skissm.MsgKey)
  if (GetArenaForAllocation() != nullptr) return;
  SharedDtor();
  _internal_metadata_.Delete<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

inline void MsgKey::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  derived_key_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}

void MsgKey::ArenaDtor(void* object) {
  MsgKey* _this = reinterpret_cast< MsgKey* >(object);
  (void)_this;
}
void MsgKey::RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena*) {
}
void MsgKey::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}

void MsgKey::Clear() {
// @@protoc_insertion_point(message_clear_start:skissm.MsgKey)
  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  derived_key_.ClearToEmpty();
  index_ = 0u;
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* MsgKey::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    uint32_t tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // uint32 index = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 8)) {
          index_ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint32(&ptr);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      // bytes derived_key = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 18)) {
          auto str = _internal_mutable_derived_key();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      default:
        goto handle_unusual;
    }  // switch
  handle_unusual:
    if ((tag == 0) || ((tag & 7) == 4)) {
      CHK_(ptr);
      ctx->SetLastTag(tag);
      goto message_done;
    }
    ptr = UnknownFieldParse(
        tag,
        _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
        ptr, ctx);
    CHK_(ptr != nullptr);
  }  // while
message_done:
  return ptr;
failure:
  ptr = nullptr;
  goto message_done;
#undef CHK_
}

uint8_t* MsgKey::_InternalSerialize(
    uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:skissm.MsgKey)
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  // uint32 index = 1;
  if (this->_internal_index() != 0) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteUInt32ToArray(1, this->_internal_index(), target);
  }

  // bytes derived_key = 2;
  if (!this->_internal_derived_key().empty()) {
    target = stream->WriteBytesMaybeAliased(
        2, this->_internal_derived_key(), target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:skissm.MsgKey)
  return target;
}

size_t MsgKey::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:skissm.MsgKey)
  size_t total_size = 0;

  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // bytes derived_key = 2;
  if (!this->_internal_derived_key().empty()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::BytesSize(
        this->_internal_derived_key());
  }

  // uint32 index = 1;
  if (this->_internal_index() != 0) {
    total_size += ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::UInt32SizePlusOne(this->_internal_index());
  }

  return MaybeComputeUnknownFieldsSize(total_size, &_cached_size_);
}

const ::PROTOBUF_NAMESPACE_ID::Message::ClassData MsgKey::_class_data_ = {
    ::PROTOBUF_NAMESPACE_ID::Message::CopyWithSizeCheck,
    MsgKey::MergeImpl
};
const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*MsgKey::GetClassData() const { return &_class_data_; }

void MsgKey::MergeImpl(::PROTOBUF_NAMESPACE_ID::Message* to,
                      const ::PROTOBUF_NAMESPACE_ID::Message& from) {
  static_cast<MsgKey *>(to)->MergeFrom(
      static_cast<const MsgKey &>(from));
}


void MsgKey::MergeFrom(const MsgKey& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:skissm.MsgKey)
  GOOGLE_DCHECK_NE(&from, this);
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  if (!from._internal_derived_key().empty()) {
    _internal_set_derived_key(from._internal_derived_key());
  }
  if (from._internal_index() != 0) {
    _internal_set_index(from._internal_index());
  }
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
}

void MsgKey::CopyFrom(const MsgKey& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:skissm.MsgKey)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool MsgKey::IsInitialized() const {
  return true;
}

void MsgKey::InternalSwap(MsgKey* other) {
  using std::swap;
  auto* lhs_arena = GetArenaForAllocation();
  auto* rhs_arena = other->GetArenaForAllocation();
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(),
      &derived_key_, lhs_arena,
      &other->derived_key_, rhs_arena
  );
  swap(index_, other->index_);
}

::PROTOBUF_NAMESPACE_ID::Metadata MsgKey::GetMetadata() const {
  return ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(
      &descriptor_table_skissm_2fMsgKey_2eproto_getter, &descriptor_table_skissm_2fMsgKey_2eproto_once,
      file_level_metadata_skissm_2fMsgKey_2eproto[0]);
}

// @@protoc_insertion_point(namespace_scope)
}  // namespace skissm
PROTOBUF_NAMESPACE_OPEN
template<> PROTOBUF_NOINLINE ::skissm::MsgKey* Arena::CreateMaybeMessage< ::skissm::MsgKey >(Arena* arena) {
  return Arena::CreateMessageInternal< ::skissm::MsgKey >(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>